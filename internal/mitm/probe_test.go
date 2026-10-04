package mitm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/evidence"
	"github.com/Infisical/agent-vault/internal/store"
)

type diagnosticCredentialStore struct{ *store.SQLStore }

func (diagnosticCredentialStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyDeny, nil
}

func TestDiagnosticUsesRealInjectionAndForwarding(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.CreateVault(ctx, "diagnostic")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	token := "123456:" + strings.Repeat("a", 30)
	service := broker.Service{Name: "telegram", Host: "api.telegram.org", Path: "/bot*/getMe", Auth: broker.Auth{Type: "passthrough"}, Substitutions: []broker.Substitution{{Key: "TOKEN", Placeholder: "DIAGNOSTIC_TOKEN", In: []string{"path"}}}}
	config, _ := json.Marshal([]broker.Service{service})
	if _, err = db.SetBrokerConfig(ctx, vault.ID, string(config)); err != nil {
		t.Fatal(err)
	}
	replace := func(value string) {
		t.Helper()
		ct, nonce, e := crypto.Encrypt([]byte(value), key)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: vault.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"test","kv_version":2}`, PollIntervalSeconds: 60, Credentials: []store.EncryptedKV{{Key: "TOKEN", Ciphertext: ct, Nonce: nonce}}}); e != nil {
			t.Fatal(e)
		}
	}
	replace(token)
	provider := brokercore.NewStoreCredentialProvider(diagnosticCredentialStore{db}, key)
	scope := &brokercore.ProxyScope{VaultID: vault.ID, VaultName: vault.Name, VaultRole: "admin", AgentID: "management"}
	sink := &recordingSink{}
	_, _, proxy := setupProxy(t, validTokenResolver("synthetic", scope), provider, func(o *Options) { o.LogSink = sink })
	for _, tc := range []struct {
		name, category, body string
		status               int
	}{
		{"ok", "ok", `{"ok":true,"result":{"token":"` + token + `"}}`, 200},
		{"reject", "rejected", token, 401},
		{"redirect", "redirect_blocked", token, 302},
		{"large", "response_too_large", strings.Repeat("x", 70000), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != "GET" || r.URL.Path != "/bot"+token+"/getMe" || r.URL.RawQuery != "" {
					t.Error("wrong final request")
				}
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("credential leak")
				}
				w.Header().Set("Location", "http://169.254.169.254/")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			transport := upstream.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "example.com"
			transport.DialContext = func(c context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(c, n, upstream.Listener.Addr().String())
			}
			defer transport.CloseIdleConnections()
			result := proxy.probeTelegram(ctx, scope, service.Name, evidence.Digest(&service), "DIAGNOSTIC_TOKEN", transport)
			if result.Category != tc.category || !result.Used || result.Loaded == nil || requests != 1 {
				t.Fatalf("result category=%s used=%v requests=%d", result.Category, result.Used, requests)
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), token) {
				t.Fatal("raw token leaked")
			}
			if len(sink.snapshot()) != 0 {
				t.Fatal("probe in general request log")
			}
			if got := evidence.Default.Recipient(vault.ID, service.Name, evidence.Digest(&service), "agent", "management", "cfg", []string{"TOKEN"}); got.State != "not_checked" {
				t.Fatal("probe became recipient ingress")
			}
		})
	}
	replace("123/../../dangerous")
	calls := 0
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, fmt.Errorf("must not dial")
	}}
	result := proxy.probeTelegram(ctx, scope, service.Name, evidence.Digest(&service), "DIAGNOSTIC_TOKEN", transport)
	if calls != 0 || result.Used {
		t.Fatal("unsafe substituted path forwarded")
	}
	replace(token)
	cancelCtx, cancel := context.WithTimeout(ctx, time.Nanosecond)
	defer cancel()
	result = proxy.probeTelegram(cancelCtx, scope, service.Name, evidence.Digest(&service), "DIAGNOSTIC_TOKEN", transport)
	if result.Used {
		t.Fatal("cancelled request forwarded")
	}
}
