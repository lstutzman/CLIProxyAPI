package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func quotaTestAuth(id, provider string, signals map[string]string, observedAt time.Time) *Auth {
	return &Auth{
		ID:       id,
		Provider: provider,
		Status:   StatusActive,
		Metadata: map[string]any{"access_token": "token-" + id},
		Quota:    QuotaState{Signals: signals, ObservedAt: observedAt},
	}
}

func unixString(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

func TestQuotaUsedPercentClaude(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	future := now.Add(2 * time.Hour)
	past := now.Add(-time.Minute)

	cases := []struct {
		name    string
		signals map[string]string
		want    float64
	}{
		{name: "no observation", signals: nil, want: 0},
		{name: "max of windows", signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization": "0.25",
			"Anthropic-Ratelimit-Unified-5h-Reset":       unixString(future),
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.6",
			"Anthropic-Ratelimit-Unified-7d-Reset":       unixString(future),
		}, want: 60},
		{name: "reset window ignored", signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization": "0.99",
			"Anthropic-Ratelimit-Unified-5h-Reset":       unixString(past),
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.1",
		}, want: 10},
		{name: "rejected window is full", signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Status":      "rejected",
			"Anthropic-Ratelimit-Unified-5h-Reset":       unixString(future),
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.1",
		}, want: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := QuotaUsedPercent(quotaTestAuth("a", "claude", tc.signals, now), now)
			if got < tc.want-0.001 || got > tc.want+0.001 {
				t.Fatalf("QuotaUsedPercent() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQuotaUsedPercentCodex(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	observed := now.Add(-10 * time.Minute)

	auth := quotaTestAuth("c", "codex", map[string]string{
		"X-Codex-Primary-Used-Percent":           "80",
		"X-Codex-Primary-Reset-After-Seconds":    "300", // reset 5m after observation, already passed
		"X-Codex-Secondary-Used-Percent":         "17",
		"X-Codex-Secondary-Reset-At":             unixString(now.Add(48 * time.Hour)),
		"X-Codex-Secondary-Window-Minutes":       "10080",
		"X-Codex-Primary-Window-Minutes":         "300",
		"X-Codex-Plan-Type":                      "pro",
		"X-Codex-Credits-Has-Credits":            "false",
		"X-Codex-Bengalfox-Primary-Used-Percent": "99",
	}, observed)
	if got := QuotaUsedPercent(auth, now); got != 17 {
		t.Fatalf("QuotaUsedPercent() = %v, want 17", got)
	}

	auth.Quota.Signals["X-Codex-Limit-Reached"] = "true"
	if got := QuotaUsedPercent(auth, now); got != 100 {
		t.Fatalf("QuotaUsedPercent() with limit reached = %v, want 100", got)
	}
}

func claudeWeeklyAuth(id, utilization string, now time.Time) *Auth {
	return quotaTestAuth(id, "claude", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": utilization,
		"Anthropic-Ratelimit-Unified-7d-Reset":       unixString(now.Add(72 * time.Hour)),
	}, now)
}

func TestQuotaAwareSelectorDrainsMostUsedBelowThreshold(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	selector := &QuotaAwareSelector{Threshold: 90, nowFunc: func() time.Time { return now }}
	a := claudeWeeklyAuth("a", "0.5", now)
	b := claudeWeeklyAuth("b", "0.3", now)
	c := claudeWeeklyAuth("c", "0", now)
	auths := []*Auth{a, b, c}

	pick := func() string {
		t.Helper()
		picked, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		return picked.ID
	}
	if got := pick(); got != "a" {
		t.Fatalf("Pick() = %s, want a (most used below threshold)", got)
	}

	// A reaches the threshold: move to B, the most-used remaining account, not the fresh C.
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.9"
	if got := pick(); got != "b" {
		t.Fatalf("Pick() = %s, want b", got)
	}

	// Every account at or above the threshold: fall back to the least used.
	b.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.95"
	c.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.92"
	if got := pick(); got != "a" {
		t.Fatalf("Pick() = %s, want a (least used when all over threshold)", got)
	}
}

func TestQuotaAwareSelectorFiveHourWindowTriggersSwitch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	selector := &QuotaAwareSelector{nowFunc: func() time.Time { return now }}
	a := claudeWeeklyAuth("a", "0.4", now)
	a.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = "0.91"
	a.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Reset"] = unixString(now.Add(time.Hour))
	b := claudeWeeklyAuth("b", "0.2", now)

	picked, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{a, b})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "b" {
		t.Fatalf("Pick() = %s, want b once a's 5h window passes the default threshold", picked.ID)
	}
}

func TestQuotaAwareSessionAffinityReleasesBindingAtThreshold(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fallback := &QuotaAwareSelector{Threshold: 90, nowFunc: func() time.Time { return now }}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: fallback, TTL: time.Hour})
	a := claudeWeeklyAuth("a", "0.5", now)
	b := claudeWeeklyAuth("b", "0.3", now)
	c := claudeWeeklyAuth("c", "0", now)
	auths := []*Auth{a, b, c}

	pickFor := func(session string) string {
		t.Helper()
		opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{session}}}
		picked, err := selector.Pick(context.Background(), "claude", "claude-sonnet-4", opts, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		return picked.ID
	}

	if got := pickFor("session-1"); got != "a" {
		t.Fatalf("session-1 = %s, want a", got)
	}
	// Below the threshold the binding holds even though usage changes.
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.89"
	if got := pickFor("session-1"); got != "a" {
		t.Fatalf("session-1 = %s, want a while below threshold", got)
	}
	// Crossing the threshold releases the binding to B, and a new session lands on B too.
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.9"
	if got := pickFor("session-1"); got != "b" {
		t.Fatalf("session-1 = %s, want b after a reached threshold", got)
	}
	if got := pickFor("session-2"); got != "b" {
		t.Fatalf("session-2 = %s, want b", got)
	}
}

func TestQuotaAwareSelectorSkipsBlockedAuth(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	blocked := quotaTestAuth("a", "claude", nil, time.Time{})
	blocked.Unavailable = true
	blocked.NextRetryAfter = now.Add(time.Hour)
	blocked.Quota.Exceeded = true
	blocked.Quota.Reason = "credential_quota"
	blocked.Quota.NextRecoverAt = now.Add(time.Hour)
	busy := quotaTestAuth("b", "claude", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.95",
	}, now)

	selector := &QuotaAwareSelector{nowFunc: func() time.Time { return now }}
	picked, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{blocked, busy})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "b" {
		t.Fatalf("Pick() = %s, want b", picked.ID)
	}
}

func TestAuthWebsocketsEnabledDefaults(t *testing.T) {
	cases := []struct {
		name string
		auth *Auth
		want bool
	}{
		{name: "codex oauth defaults on", auth: &Auth{Provider: "codex", Metadata: map[string]any{"refresh_token": "r"}}, want: true},
		{name: "codex oauth explicit off", auth: &Auth{Provider: "codex", Metadata: map[string]any{"refresh_token": "r", "websockets": false}}, want: false},
		{name: "codex api key defaults off", auth: &Auth{Provider: "codex", Attributes: map[string]string{"api_key": "k"}}, want: false},
		{name: "codex api key opt in", auth: &Auth{Provider: "codex", Attributes: map[string]string{"api_key": "k", "websockets": "true"}}, want: true},
		{name: "claude oauth off", auth: &Auth{Provider: "claude", Metadata: map[string]any{"refresh_token": "r"}}, want: false},
		{name: "nil", auth: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.auth.WebsocketsEnabled(); got != tc.want {
				t.Fatalf("WebsocketsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
