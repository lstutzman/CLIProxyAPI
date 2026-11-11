package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const accountSelectorModel = "account-selector-model"

type accountSelectorFixture struct {
	manager  *Manager
	mu       sync.Mutex
	served   []string
	failures map[string]error
}

func (f *accountSelectorFixture) servedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.served...)
}

func (f *accountSelectorFixture) resetServed() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.served = nil
}

// newAccountSelectorFixture builds a manager on the production routing stack (session affinity
// over a quota-aware selector). Weekly usage: heavy 50%, mid 30%, reserve 95% (listed reserve).
func newAccountSelectorFixture(t *testing.T) *accountSelectorFixture {
	t.Helper()
	now := time.Now()
	quota := &QuotaAwareSelector{Threshold: 100, AccountThresholds: map[string]float64{"reserve@example.com": 90}}
	selector := NewSessionAffinitySelector(quota)
	t.Cleanup(selector.Stop)
	f := &accountSelectorFixture{manager: NewManager(nil, selector, nil), failures: map[string]error{}}
	f.manager.SetRetryConfig(0, 0, 0)

	for _, spec := range []struct {
		email string
		used  float64
	}{{"heavy@example.com", 50}, {"mid@example.com", 30}, {"reserve@example.com", 95}} {
		id := "claude-" + spec.email + ".json"
		auth := &Auth{
			ID: id, FileName: id, Provider: "claude", Label: spec.email, Status: StatusActive,
			Metadata: map[string]any{"email": spec.email, "access_token": "token-" + spec.email},
			Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
				"anthropic-ratelimit-unified-7d-utilization": strconv.FormatFloat(spec.used/100, 'f', 2, 64),
				"anthropic-ratelimit-unified-7d-reset":       strconv.FormatInt(now.Add(72*time.Hour).Unix(), 10),
			}},
		}
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: accountSelectorModel}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, err := f.manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}
	f.manager.RegisterExecutor(&mockCustomErrorExecutor{
		identifier: "claude",
		executeFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			f.mu.Lock()
			f.served = append(f.served, auth.Metadata["email"].(string))
			failure := f.failures[auth.ID]
			f.mu.Unlock()
			if failure != nil {
				return cliproxyexecutor.Response{}, failure
			}
			return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
		},
	})
	return f
}

func (f *accountSelectorFixture) execute(account, session string) (string, error) {
	opts := cliproxyexecutor.Options{Metadata: map[string]any{}}
	if account != "" {
		opts.Metadata[cliproxyexecutor.RequestedAccountMetadataKey] = account
	}
	if session != "" {
		opts.Headers = http.Header{"X-Session-Id": []string{session}}
	}
	resp, err := f.manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: accountSelectorModel}, opts)
	return string(resp.Payload), err
}

func accountSelectorError(t *testing.T, err error) *Error {
	t.Helper()
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		t.Fatalf("want an auth error, got %v", err)
	}
	return authErr
}

func TestAccountSelectorAbsentHeaderKeepsQuotaAwareRouting(t *testing.T) {
	f := newAccountSelectorFixture(t)
	// Quota-aware drains the most-used account below its threshold; the reserve is past its own.
	for i := 0; i < 3; i++ {
		if _, err := f.execute("", ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range f.servedIDs() {
		if email != "heavy@example.com" {
			t.Fatalf("unnamed requests must follow quota-aware routing, served by %v", f.servedIDs())
		}
	}
	// Session affinity still binds an unnamed session to one account.
	f.resetServed()
	for i := 0; i < 2; i++ {
		if _, err := f.execute("", "session-unnamed"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.servedIDs(); len(got) != 2 || got[0] != got[1] {
		t.Fatalf("session affinity must stay sticky, got %v", got)
	}
}

func TestAccountSelectorNamedAccountServesTheRequest(t *testing.T) {
	f := newAccountSelectorFixture(t)
	for _, name := range []string{"mid@example.com", "MID@Example.com", "  mid@example.com ", "claude-mid@example.com.json"} {
		f.resetServed()
		if _, err := f.execute(name, ""); err != nil {
			t.Fatalf("name %q: %v", name, err)
		}
		if got := f.servedIDs(); len(got) != 1 || got[0] != "mid@example.com" {
			t.Fatalf("name %q served by %v, want mid@example.com", name, got)
		}
	}
	// A listed reserve account past its threshold is never picked by routing but a named
	// request still reaches it: the caller asked for exactly that account.
	f.resetServed()
	if _, err := f.execute("reserve@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if got := f.servedIDs(); len(got) != 1 || got[0] != "reserve@example.com" {
		t.Fatalf("named reserve account served by %v", got)
	}
}

func TestAccountSelectorUnknownAccountIsRefused(t *testing.T) {
	f := newAccountSelectorFixture(t)
	_, err := f.execute("nobody@example.com", "")
	authErr := accountSelectorError(t, err)
	if authErr.Code != ErrorCodeAccountNotFound || authErr.HTTPStatus != http.StatusNotFound {
		t.Fatalf("unknown account: code=%q status=%d", authErr.Code, authErr.HTTPStatus)
	}
	if len(f.servedIDs()) != 0 {
		t.Fatalf("an unknown account must not reach any upstream, served by %v", f.servedIDs())
	}
}

func TestAccountSelectorDisabledAccountIsRefused(t *testing.T) {
	f := newAccountSelectorFixture(t)
	disabled, ok := f.manager.GetByID("claude-mid@example.com.json")
	if !ok {
		t.Fatal("fixture auth missing")
	}
	disabled.Disabled, disabled.Status = true, StatusDisabled
	if _, err := f.manager.Update(context.Background(), disabled); err != nil {
		t.Fatal(err)
	}
	_, err := f.execute("mid@example.com", "")
	authErr := accountSelectorError(t, err)
	if authErr.Code != ErrorCodeAccountDisabled || authErr.HTTPStatus != http.StatusForbidden {
		t.Fatalf("disabled account: code=%q status=%d", authErr.Code, authErr.HTTPStatus)
	}
	if len(f.servedIDs()) != 0 {
		t.Fatalf("a disabled account must not be replaced, served by %v", f.servedIDs())
	}
}

func TestAccountSelectorNeverFallsBackToAnotherAccount(t *testing.T) {
	f := newAccountSelectorFixture(t)

	// Cooling down: the cooldown surfaces as 429 and nothing else serves the request.
	retryAfter := time.Hour
	f.manager.MarkResult(context.Background(), Result{
		AuthID: "claude-mid@example.com.json", Provider: "claude", Model: accountSelectorModel, RetryAfter: &retryAfter,
		Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "model quota"},
	})
	_, err := f.execute("mid@example.com", "")
	if err == nil {
		t.Fatal("a cooling-down named account must fail the request")
	}
	if status := statusCodeFromError(err); status != http.StatusTooManyRequests {
		t.Fatalf("cooling-down account status = %d, want 429 (err %v)", status, err)
	}
	if len(f.servedIDs()) != 0 {
		t.Fatalf("a cooling-down account must not fall back, served by %v", f.servedIDs())
	}

	// Upstream failure on the named account: retries stay on that account.
	f.manager.SetRetryConfig(2, time.Second, 0)
	f.failures["claude-heavy@example.com.json"] = &Error{HTTPStatus: http.StatusBadGateway, Message: "upstream down"}
	if _, err = f.execute("heavy@example.com", ""); err == nil {
		t.Fatal("an upstream failure on the named account must fail the request")
	}
	for _, email := range f.servedIDs() {
		if email != "heavy@example.com" {
			t.Fatalf("failure on the named account must never move to another account, served by %v", f.servedIDs())
		}
	}
}

func TestAccountSelectorNamedRequestDoesNotTouchSessionBinding(t *testing.T) {
	f := newAccountSelectorFixture(t)

	// An unnamed request binds the session to the quota-aware choice.
	if _, err := f.execute("", "session-sticky"); err != nil {
		t.Fatal(err)
	}
	bound := f.servedIDs()[0]
	if bound != "heavy@example.com" {
		t.Fatalf("fixture expects the session to bind to heavy, got %s", bound)
	}

	// A named request on the same session goes to the named account and does not rebind it.
	f.resetServed()
	if _, err := f.execute("mid@example.com", "session-sticky"); err != nil {
		t.Fatal(err)
	}
	if got := f.servedIDs(); len(got) != 1 || got[0] != "mid@example.com" {
		t.Fatalf("named request on a bound session served by %v, want mid", got)
	}
	f.resetServed()
	if _, err := f.execute("", "session-sticky"); err != nil {
		t.Fatal(err)
	}
	if got := f.servedIDs(); len(got) != 1 || got[0] != bound {
		t.Fatalf("session binding moved after a named request: served by %v, want %s", got, bound)
	}

	// A named request on a fresh session creates no binding either.
	f.resetServed()
	if _, err := f.execute("mid@example.com", "session-fresh"); err != nil {
		t.Fatal(err)
	}
	f.resetServed()
	if _, err := f.execute("", "session-fresh"); err != nil {
		t.Fatal(err)
	}
	if got := f.servedIDs(); len(got) != 1 || got[0] != "heavy@example.com" {
		t.Fatalf("a named request must not bind its session; next unnamed request served by %v", got)
	}
}

func TestAccountSelectorRejectsAmbiguousAndConflictingNames(t *testing.T) {
	f := newAccountSelectorFixture(t)
	duplicate := &Auth{
		ID: "claude-mid-copy.json", FileName: "claude-mid-copy.json", Provider: "claude", Label: "mid@example.com", Status: StatusActive,
		Metadata: map[string]any{"email": "mid@example.com", "access_token": "token-copy"},
	}
	registry.GetGlobalRegistry().RegisterClient(duplicate.ID, "claude", []*registry.ModelInfo{{ID: accountSelectorModel}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(duplicate.ID) })
	if _, err := f.manager.Register(context.Background(), duplicate); err != nil {
		t.Fatal(err)
	}
	_, err := f.execute("mid@example.com", "")
	if authErr := accountSelectorError(t, err); authErr.Code != ErrorCodeAccountAmbiguous || authErr.HTTPStatus != http.StatusConflict {
		t.Fatalf("ambiguous name: code=%q status=%d", authErr.Code, authErr.HTTPStatus)
	}
	if len(f.servedIDs()) != 0 {
		t.Fatalf("an ambiguous name must not reach any upstream, served by %v", f.servedIDs())
	}
	// The file name stays an unambiguous handle.
	if _, err = f.execute("claude-mid-copy.json", ""); err != nil {
		t.Fatal(err)
	}
}

func TestAccountSelectorMatchesNoCredentialMaterial(t *testing.T) {
	auth := &Auth{
		ID: "id", Provider: "claude", Label: "claude-apikey",
		Attributes: map[string]string{AttributeAPIKey: "sk-secret-value"},
		Metadata:   map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret"},
	}
	for _, secret := range []string{"sk-secret-value", "access-secret", "refresh-secret"} {
		if accountMatches(auth, secret) {
			t.Fatalf("account name must never match credential material %q", secret)
		}
	}
}

func TestAccountSelectorAppliesToStreamingRequests(t *testing.T) {
	f := newAccountSelectorFixture(t)
	f.manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "claude",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			f.mu.Lock()
			f.served = append(f.served, auth.Metadata["email"].(string))
			f.mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("chunk")}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	opts := cliproxyexecutor.Options{Stream: true, Metadata: map[string]any{cliproxyexecutor.RequestedAccountMetadataKey: "mid@example.com"}}
	result, err := f.manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: accountSelectorModel}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for range result.Chunks {
	}
	if got := f.servedIDs(); len(got) != 1 || got[0] != "mid@example.com" {
		t.Fatalf("named streaming request served by %v", got)
	}

	opts.Metadata = map[string]any{cliproxyexecutor.RequestedAccountMetadataKey: "nobody@example.com"}
	if _, err = f.manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: accountSelectorModel}, opts); accountSelectorError(t, err).Code != ErrorCodeAccountNotFound {
		t.Fatalf("unknown account on a streaming request: %v", err)
	}
}

func TestAccountSelectorFailsClosedOnUnresolvedSelectionPaths(t *testing.T) {
	f := newAccountSelectorFixture(t)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.RequestedAccountMetadataKey: "mid@example.com"}}
	if _, err := f.manager.SelectAuth(context.Background(), "claude", accountSelectorModel, opts); accountSelectorError(t, err).Code != ErrorCodeAccountUnsupported {
		t.Fatalf("SelectAuth with an unresolved account must fail closed, got %v", err)
	}
	if _, err := f.manager.SelectAuthByKind(context.Background(), "claude", accountSelectorModel, "oauth", opts); accountSelectorError(t, err).Code != ErrorCodeAccountUnsupported {
		t.Fatalf("SelectAuthByKind with an unresolved account must fail closed, got %v", err)
	}
	// Without a named account the same entry points are unchanged.
	if picked, err := f.manager.SelectAuth(context.Background(), "claude", accountSelectorModel, cliproxyexecutor.Options{}); err != nil || picked == nil {
		t.Fatalf("SelectAuth without a named account: %v %v", picked, err)
	}
}
