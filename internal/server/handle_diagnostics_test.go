package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/evidence"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

type diagnosticFetcher struct {
	value   string
	version int
	hook    func()
}

func (*diagnosticFetcher) AuthMethod() hashicorp.AuthMethod { return hashicorp.AuthToken }
func (f *diagnosticFetcher) FetchSecrets(ctx context.Context, c hashicorp.VaultConfig) ([]hashicorp.Secret, error) {
	s, e := f.FetchSnapshot(ctx, c)
	return s.Secrets, e
}
func (f *diagnosticFetcher) FetchSnapshot(context.Context, hashicorp.VaultConfig) (hashicorp.Snapshot, error) {
	if f.hook != nil {
		f.hook()
	}
	v := f.version
	return hashicorp.Snapshot{Version: &v, ObservedAt: time.Now().UTC(), Secrets: []hashicorp.Secret{{Key: "TOKEN", Value: f.value}, {Key: "UNRELATED", Value: "never returned"}}}, nil
}

func TestDiagnosticPrivateAPIAndRevocation(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.CreateVault(ctx, "diagnostic")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := db.CreateAgent(ctx, "management", "test", "member")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := db.CreateAgent(ctx, "recipient", "test", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ id, role string }{{manager.ID, "admin"}, {recipient.ID, "proxy"}} {
		if err = db.GrantVaultRole(ctx, grant.id, "agent", vault.ID, grant.role); err != nil {
			t.Fatal(err)
		}
	}
	token, err := db.CreateAgentToken(ctx, manager.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	services := `[{"name":"telegram","host":"api.telegram.org/bot*/getMe","auth":{"type":"passthrough"},"substitutions":[{"key":"TOKEN","placeholder":"TOKEN_PLACEHOLDER","in":["path"]}]}]`
	if _, err = db.SetBrokerConfig(ctx, vault.ID, services); err != nil {
		t.Fatal(err)
	}
	cs, err := db.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{VaultID: vault.ID, Kind: store.CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"test","kv_version":2}`, PollIntervalSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	fetcher := &diagnosticFetcher{value: "123456:" + strings.Repeat("a", 30), version: 17}
	logger := slog.New(slog.DiscardHandler)
	syncer := hashicorp.NewSyncer(db, fetcher, key, logger)
	if err = syncer.RefreshOnce(ctx, *cs); err != nil {
		t.Fatal(err)
	}
	srv := New("127.0.0.1:0", db, key, nil, true, "http://127.0.0.1:14321", logger)
	srv.AttachHashicorpSyncer(syncer)
	input := diagnosticRequest{Version: 1, Operation: "evidence", Service: "telegram", Keys: []string{"TOKEN"}, RecipientType: "agent", RecipientID: recipient.ID}
	call := func(auth string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, "/v1/vaults/diagnostic/diagnostics", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, r)
		return w
	}
	w := call(token.ID, input)
	if w.Code != 200 {
		t.Fatalf("diagnostic: %d %s", w.Code, w.Body.String())
	}
	var answer diagnosticResponse
	if err = json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" || answer.Loaded.State != "matched" || answer.Loaded.CopyVersion == nil || *answer.Loaded.CopyVersion != 17 || answer.RecipientIngress.State != "not_checked" {
		t.Fatalf("bad evidence %+v", answer)
	}
	if len(answer.Loaded.Fields) != 1 || len(answer.Loaded.CopyFields) != 1 || strings.Contains(w.Body.String(), "UNRELATED") || strings.Contains(w.Body.String(), fetcher.value) {
		t.Fatal("diagnostic leaks nonselected or raw values")
	}
	if answer.Loaded.Fields["TOKEN"] != evidence.Default.Fingerprint(fetcher.value) {
		t.Fatal("wrong actual fingerprint")
	}
	fetcher.value = "lost-character"
	fetcher.version = 18
	w = call(token.ID, input)
	_ = json.Unmarshal(w.Body.Bytes(), &answer)
	if answer.Loaded.State != "mismatch" {
		t.Fatal("stale loaded value not detected")
	}
	if call("", input).Code != 401 {
		t.Fatal("unauthenticated evidence")
	}
	original := input
	input.Keys = []string{"TOKEN", "UNRELATED"}
	if call(token.ID, input).Code != 403 {
		t.Fatal("arbitrary key disclosure")
	}
	input = original
	input.Operation = "telegram_get_me"
	if call(token.ID, input).Code != 400 {
		t.Fatal("probe without opt-in")
	}
	input = original
	fetcher.hook = func() {
		if e := db.RevokeVaultAccess(ctx, recipient.ID, vault.ID); e != nil {
			t.Fatal(e)
		}
	}
	if w = call(token.ID, input); w.Code != 409 {
		t.Fatalf("revocation race: %d %s", w.Code, w.Body.String())
	}
	if call(token.ID, input).Code != 403 {
		t.Fatal("revoked membership")
	}
}
