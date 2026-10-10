package auth

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// DefaultQuotaThreshold is the used-quota percentage at which the quota-aware strategy
// stops sending work to a credential.
const DefaultQuotaThreshold = 90.0

// QuotaAwareSelector concentrates work on one credential at a time, switching only when a
// subscription window reaches the threshold. Among credentials below Threshold it picks
// the most-used one, so partially consumed accounts are drained before fresh ones and
// every session converges on the same account. When every credential is at or above
// Threshold it picks the least-used one.
//
// Usage comes from the passive rate-limit snapshot recorded on every upstream response
// (Claude unified 5h/7d windows, Codex primary/secondary windows), so it costs no extra
// upstream requests. Credentials without a snapshot count as unused.
type QuotaAwareSelector struct {
	// Threshold is the used percentage (0-100] at which a credential is skipped.
	// Non-positive or out-of-range values use DefaultQuotaThreshold.
	Threshold float64
	// AccountThresholds overrides Threshold per account email (lower-case keys). A listed
	// account is a reserve: it is never picked at or above its own threshold.
	AccountThresholds map[string]float64
	nowFunc           func() time.Time
}

// thresholdFor returns the credential's own threshold and whether it is a reserve.
func (s *QuotaAwareSelector) thresholdFor(auth *Auth) (float64, bool) {
	if s != nil && len(s.AccountThresholds) > 0 {
		if _, email := auth.AccountInfo(); email != "" {
			if t, ok := s.AccountThresholds[strings.ToLower(strings.TrimSpace(email))]; ok {
				return t, true
			}
		}
	}
	return s.threshold(), false
}

func (s *QuotaAwareSelector) now() time.Time {
	if s != nil && s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

func (s *QuotaAwareSelector) threshold() float64 {
	if s == nil || s.Threshold <= 0 || s.Threshold > 100 {
		return DefaultQuotaThreshold
	}
	return s.Threshold
}

// Pick selects the most-used credential below the threshold, or the least-used one when
// every credential has reached it. Ties resolve to the lowest credential ID.
func (s *QuotaAwareSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)

	var under, over *Auth
	underUsed, overUsed := -1.0, math.Inf(1)
	for _, candidate := range available {
		used := QuotaUsedPercent(candidate, now)
		threshold, reserve := s.thresholdFor(candidate)
		if used >= threshold && reserve {
			continue
		}
		if used < threshold {
			if used > underUsed {
				under, underUsed = candidate, used
			}
		} else if used < overUsed {
			over, overUsed = candidate, used
		}
	}
	if under != nil {
		return under, nil
	}
	if over == nil {
		return nil, &Error{Code: "auth_not_found", Message: "every available credential is spent or held in reserve"}
	}
	return over, nil
}

// filterAffinityCandidates drops credentials at or above the threshold so session
// affinity releases a binding once its credential crosses it. The input is returned
// unchanged when no credential is below the threshold.
func (s *QuotaAwareSelector) filterAffinityCandidates(auths []*Auth) []*Auth {
	now := s.now()
	under := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		threshold, _ := s.thresholdFor(auth)
		if QuotaUsedPercent(auth, now) < threshold {
			under = append(under, auth)
		}
	}
	if len(under) == 0 {
		return auths
	}
	return under
}

// QuotaUsedPercent returns the highest used percentage (0-100) across the credential's
// observed subscription windows. Windows whose reset time has passed count as 0, and a
// credential without any observation returns 0.
func QuotaUsedPercent(auth *Auth, now time.Time) float64 {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return 0
	}
	signals := auth.Quota.Signals
	used := 0.0
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		for _, window := range []string{"5h", "7d"} {
			prefix := "anthropic-ratelimit-unified-" + window + "-"
			reset, hasReset := quotaSignalUnix(signals, prefix+"reset")
			if hasReset && !reset.After(now) {
				continue
			}
			if strings.EqualFold(quotaSignal(signals, prefix+"status"), "rejected") {
				return 100
			}
			if utilization, ok := quotaSignalFloat(signals, prefix+"utilization"); ok {
				used = math.Max(used, utilization*100)
			}
		}
	case "codex":
		anyActiveWindow := false
		for _, window := range []string{"primary", "secondary"} {
			prefix := "x-codex-" + window + "-"
			percent, ok := quotaSignalFloat(signals, prefix+"used-percent")
			if !ok {
				continue
			}
			reset, hasReset := quotaSignalUnix(signals, prefix+"reset-at")
			if !hasReset {
				if after, okAfter := quotaSignalFloat(signals, prefix+"reset-after-seconds"); okAfter && !auth.Quota.ObservedAt.IsZero() {
					reset, hasReset = auth.Quota.ObservedAt.Add(time.Duration(after*float64(time.Second))), true
				}
			}
			if hasReset && !reset.After(now) {
				continue
			}
			anyActiveWindow = true
			used = math.Max(used, percent)
		}
		if anyActiveWindow && strings.EqualFold(quotaSignal(signals, "x-codex-limit-reached"), "true") {
			return 100
		}
	}
	return math.Min(math.Max(used, 0), 100)
}

func quotaSignal(signals map[string]string, name string) string {
	if value, ok := signals[http.CanonicalHeaderKey(name)]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range signals {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func quotaSignalFloat(signals map[string]string, name string) (float64, bool) {
	raw := quotaSignal(signals, name)
	if raw == "" {
		return 0, false
	}
	value, errParse := strconv.ParseFloat(raw, 64)
	if errParse != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

func quotaSignalUnix(signals map[string]string, name string) (time.Time, bool) {
	value, ok := quotaSignalFloat(signals, name)
	if !ok || value <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(value), 0), true
}
