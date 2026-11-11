package auth

import (
	"net/http"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Error codes returned when a client names an account with the X-CPA-Account header.
const (
	// ErrorCodeAccountNotFound reports that no credential matches the named account.
	ErrorCodeAccountNotFound = "account_not_found"
	// ErrorCodeAccountDisabled reports that the named account is disabled.
	ErrorCodeAccountDisabled = "account_disabled"
	// ErrorCodeAccountAmbiguous reports that the name matches more than one credential.
	ErrorCodeAccountAmbiguous = "account_ambiguous"
	// ErrorCodeAccountUnsupported reports that the runtime cannot honor a named account.
	ErrorCodeAccountUnsupported = "account_selector_unsupported"
)

// explicitAccountFromMetadata reports whether the request was pinned by a client-named account.
func explicitAccountFromMetadata(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	explicit, _ := meta[cliproxyexecutor.ExplicitAccountMetadataKey].(bool)
	return explicit
}

func requestedAccountFromMetadata(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	raw, _ := meta[cliproxyexecutor.RequestedAccountMetadataKey].(string)
	return strings.TrimSpace(raw)
}

// accountMatches reports whether name identifies auth by its label, its account email, its ID or
// its auth file name. Only those identifiers are compared, never credential material.
func accountMatches(auth *Auth, name string) bool {
	if auth == nil || name == "" {
		return false
	}
	if auth.ID == name || (auth.FileName != "" && auth.FileName == name) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(auth.Label), name) {
		return true
	}
	if auth.Metadata != nil {
		if email, ok := auth.Metadata["email"].(string); ok && strings.EqualFold(strings.TrimSpace(email), name) {
			return true
		}
	}
	return false
}

// applyRequestedAccount resolves a client-named account (X-CPA-Account) to one credential of the
// request's providers and pins the request to it. Without a named account opts is returned
// unchanged. An unknown, disabled or ambiguous name fails the request; the request never falls
// back to another account.
func (m *Manager) applyRequestedAccount(providers []string, opts cliproxyexecutor.Options) (cliproxyexecutor.Options, error) {
	name := requestedAccountFromMetadata(opts.Metadata)
	if name == "" {
		return opts, nil
	}
	if m.HomeEnabled() {
		return opts, &Error{Code: ErrorCodeAccountUnsupported, Message: "naming an account is not supported while Home is enabled", HTTPStatus: http.StatusNotImplemented}
	}
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		providerSet[canonicalSchedulingProvider(provider)] = struct{}{}
	}

	var matched *Auth
	matches := 0
	m.mu.RLock()
	for _, candidate := range m.auths {
		if candidate == nil {
			continue
		}
		if _, ok := providerSet[canonicalSchedulingProvider(executorKeyFromAuth(candidate))]; !ok {
			continue
		}
		if !accountMatches(candidate, name) {
			continue
		}
		matches++
		matched = candidate
	}
	var matchedID string
	var matchedDisabled bool
	if matches == 1 {
		matchedID = matched.ID
		matchedDisabled = matched.Disabled || matched.Status == StatusDisabled
	}
	m.mu.RUnlock()

	switch {
	case matches == 0:
		return opts, &Error{Code: ErrorCodeAccountNotFound, Message: "no credential matches the requested account", HTTPStatus: http.StatusNotFound}
	case matches > 1:
		return opts, &Error{Code: ErrorCodeAccountAmbiguous, Message: "the requested account matches more than one credential", HTTPStatus: http.StatusConflict}
	case matchedDisabled:
		return opts, &Error{Code: ErrorCodeAccountDisabled, Message: "the requested account is disabled", HTTPStatus: http.StatusForbidden}
	}
	if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" && pinned != matchedID {
		return opts, &Error{Code: ErrorCodeAccountAmbiguous, Message: "the requested account conflicts with the pinned credential", HTTPStatus: http.StatusConflict}
	}

	meta := make(map[string]any, len(opts.Metadata)+2)
	for key, value := range opts.Metadata {
		meta[key] = value
	}
	meta[cliproxyexecutor.PinnedAuthMetadataKey] = matchedID
	meta[cliproxyexecutor.ExplicitAccountMetadataKey] = true
	opts.Metadata = meta
	return opts, nil
}

// firstAuth returns the first credential, or nil for an empty list.
func firstAuth(auths []*Auth) *Auth {
	if len(auths) == 0 {
		return nil
	}
	return auths[0]
}

// unresolvedAccountError fails closed when a request still carries a client-named account that
// applyRequestedAccount did not resolve (for example a selection entry point that skips it), so a
// named request can never be routed by the strategy instead.
func unresolvedAccountError(opts cliproxyexecutor.Options) error {
	if requestedAccountFromMetadata(opts.Metadata) == "" || explicitAccountFromMetadata(opts.Metadata) {
		return nil
	}
	return &Error{Code: ErrorCodeAccountUnsupported, Message: "naming an account is not supported on this selection path", HTTPStatus: http.StatusNotImplemented}
}
