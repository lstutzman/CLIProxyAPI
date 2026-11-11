package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
)

type staticAccessProvider struct {
	principal string
}

func (p staticAccessProvider) Identifier() string { return "static-test" }

func (p staticAccessProvider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if r.Header.Get("Authorization") == "Bearer test-key" {
		return &sdkaccess.Result{Provider: "static-test", Principal: p.principal}, nil
	}
	return nil, sdkaccess.NewNoCredentialsError()
}

func accountSelectorStatus(t *testing.T, manager *sdkaccess.Manager, authorization, account string) (int, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	reached := false
	engine := gin.New()
	engine.Use(AuthMiddleware(manager))
	engine.GET("/v1/models", func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if account != "" {
		req.Header.Set(handlers.RequestedAccountHeader, account)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec.Code, reached
}

func TestAccountSelectorHeaderRequiresAnAPIKey(t *testing.T) {
	withKey := sdkaccess.NewManager()
	withKey.SetProviders([]sdkaccess.Provider{staticAccessProvider{principal: "key-1"}})

	if code, reached := accountSelectorStatus(t, withKey, "Bearer test-key", "mid@example.com"); code != http.StatusOK || !reached {
		t.Fatalf("API-key request naming an account: status=%d reached=%v", code, reached)
	}
	if code, reached := accountSelectorStatus(t, withKey, "Bearer test-key", ""); code != http.StatusOK || !reached {
		t.Fatalf("API-key request without the header must be unchanged: status=%d reached=%v", code, reached)
	}
	if code, reached := accountSelectorStatus(t, withKey, "Bearer wrong", "mid@example.com"); code != http.StatusUnauthorized || reached {
		t.Fatalf("a bad key must still be refused: status=%d reached=%v", code, reached)
	}

	// No access provider configured: the legacy open mode must not let a caller pick an account.
	open := sdkaccess.NewManager()
	if code, reached := accountSelectorStatus(t, open, "", "mid@example.com"); code != http.StatusUnauthorized || reached {
		t.Fatalf("open access naming an account: status=%d reached=%v", code, reached)
	}
	if code, reached := accountSelectorStatus(t, open, "", ""); code != http.StatusOK || !reached {
		t.Fatalf("open access without the header must be unchanged: status=%d reached=%v", code, reached)
	}
	if code, reached := accountSelectorStatus(t, nil, "", "mid@example.com"); code != http.StatusUnauthorized || reached {
		t.Fatalf("nil manager naming an account: status=%d reached=%v", code, reached)
	}
}
