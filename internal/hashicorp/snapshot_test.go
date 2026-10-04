package hashicorp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestSnapshotCapturesActualKVProvenance(t *testing.T) {
	created := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	now := created.Add(time.Hour)
	for _, tc := range []struct {
		name, body string
		kv         int
		wantError  bool
	}{
		{"kv2", `{"data":{"data":{"TOKEN":"снег"},"metadata":{"version":37,"created_time":"2026-10-04T00:00:00Z"}}}`, 2, false},
		{"kv1", `{"data":{"TOKEN":"снег"}}`, 1, false},
		{"missing_metadata", `{"data":{"data":{"TOKEN":"снег"}}}`, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			cfg := vaultapi.DefaultConfig()
			cfg.Address = server.URL
			api, err := vaultapi.NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{api: api, method: AuthToken, clock: func() time.Time { return now }, logger: slog.New(slog.DiscardHandler)}
			got, err := c.FetchSnapshot(context.Background(), VaultConfig{Mount: "secret", SecretPath: "test", KVVersion: tc.kv})
			if tc.wantError {
				if err == nil {
					t.Fatal("missing provenance accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Secrets) != 1 || got.Secrets[0].Value != "снег" || !got.ObservedAt.Equal(now) {
				t.Fatal("wrong actual snapshot")
			}
			if tc.kv == 1 && got.Version != nil {
				t.Fatal("invented KV1 version")
			}
			if tc.kv == 2 && (got.Version == nil || *got.Version != 37 || !got.CreatedAt.Equal(created)) {
				t.Fatal("lost KV2 provenance")
			}
		})
	}
}
