package hashicorp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// approleStub serves an AppRole login that mints numbered tokens with the given
// TTL and a KV v2 read that only accepts the most recently issued token.
func approleStub(t *testing.T, ttlSecs int, logins *atomic.Int32) *httptest.Server {
	t.Helper()
	var current atomic.Value
	current.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			n := logins.Add(1)
			tok := "tok-" + string(rune('0'+n))
			current.Store(tok)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": tok, "lease_duration": ttlSecs, "renewable": true},
			})
		case "/v1/secret/data/app":
			if r.Header.Get("X-Vault-Token") != current.Load().(string) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     map[string]interface{}{"API_KEY": "v"},
					"metadata": map[string]interface{}{"version": 1},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newAppRoleClient(t *testing.T, url string, clock func() time.Time) *Client {
	t.Helper()
	t.Setenv("VAULT_ROLE_ID", "r")
	t.Setenv("VAULT_SECRET_ID", "s")
	cfg := vaultapi.DefaultConfig()
	cfg.Address = url
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault api client: %v", err)
	}
	c := &Client{api: api, method: AuthAppRole, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), clock: clock}
	if err := c.login(context.Background()); err != nil {
		t.Fatalf("login: %v", err)
	}
	return c
}

// TestFetchSecrets_AppRoleReloginBeforeExpiry: once the fake clock passes two
// thirds of the token TTL, the next fetch re-authenticates before reading.
func TestFetchSecrets_AppRoleReloginBeforeExpiry(t *testing.T) {
	var logins atomic.Int32
	srv := approleStub(t, 300, &logins)
	now := time.Unix(1_700_000_000, 0)
	c := newAppRoleClient(t, srv.URL, func() time.Time { return now })
	cfg := VaultConfig{Mount: "secret", SecretPath: "app", KVVersion: 2}

	if _, err := c.FetchSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if got := logins.Load(); got != 1 {
		t.Fatalf("logins after first fetch = %d, want 1", got)
	}

	now = now.Add(150 * time.Second) // half the TTL: still fresh
	if _, err := c.FetchSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := logins.Load(); got != 1 {
		t.Fatalf("logins at half TTL = %d, want 1", got)
	}

	now = now.Add(60 * time.Second) // 210s > 200s (two thirds of 300s)
	if _, err := c.FetchSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("third fetch: %v", err)
	}
	if got := logins.Load(); got != 2 {
		t.Fatalf("logins past two-thirds TTL = %d, want 2", got)
	}
}

// TestFetchSecrets_AppRoleReloginOn403: a token revoked upstream (before its
// scheduled expiry) yields a 403; the client re-logs in once and retries.
func TestFetchSecrets_AppRoleReloginOn403(t *testing.T) {
	var logins atomic.Int32
	srv := approleStub(t, 300, &logins)
	c := newAppRoleClient(t, srv.URL, time.Now)
	cfg := VaultConfig{Mount: "secret", SecretPath: "app", KVVersion: 2}

	// Simulate revocation: the stub only honours the latest token, so a
	// stale token on the client is rejected with 403.
	c.api.SetToken("revoked")
	secs, err := c.FetchSecrets(context.Background(), cfg)
	if err != nil {
		t.Fatalf("fetch after revocation: %v", err)
	}
	if len(secs) != 1 || secs[0].Key != "API_KEY" {
		t.Fatalf("secrets = %+v, want API_KEY", secs)
	}
	if got := logins.Load(); got != 2 {
		t.Fatalf("logins = %d, want 2 (initial + re-login on 403)", got)
	}
}

// TestFetchSecrets_TokenAuthNo403Retry: VAULT_TOKEN auth has nothing to
// re-login with, so a 403 surfaces as-is.
func TestFetchSecrets_TokenAuthNo403Retry(t *testing.T) {
	var logins atomic.Int32
	srv := approleStub(t, 300, &logins)
	c := newClientForServer(t, srv.URL) // token auth, "stub-token" never valid
	if _, err := c.FetchSecrets(context.Background(), VaultConfig{Mount: "secret", SecretPath: "app", KVVersion: 2}); err == nil || !isPermissionDenied(err) {
		t.Fatalf("err = %v, want a 403 ResponseError", err)
	}
	if got := logins.Load(); got != 0 {
		t.Fatalf("logins = %d, want 0", got)
	}
}
