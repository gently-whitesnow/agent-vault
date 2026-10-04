package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/evidence"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

var telegramTokenPath = regexp.MustCompile(`^/bot[0-9]{1,20}:[A-Za-z0-9_-]{20,128}/getMe$`)

type probeContextKey struct{}

type probeExecution struct {
	Service   string
	Rule      string
	RequestID string
	Loaded    *evidence.Loaded
	Used      bool
	Category  string
}

type ProbeResult struct {
	Evidence  *evidence.Result `json:"evidence,omitempty"`
	Category  string           `json:"category"`
	RequestID string           `json:"request_id"`
	Loaded    *evidence.Loaded `json:"-"`
	Used      bool             `json:"-"`
}

type probeResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (r *probeResponse) Header() http.Header    { return r.header }
func (r *probeResponse) WriteHeader(status int) { r.status = status }
func (r *probeResponse) Write(data []byte) (int, error) {
	if r.body.Len()+len(data) > 65536 {
		r.overflow = true
		return 0, errors.New("response limit")
	}
	return r.body.Write(data)
}

func (p *Proxy) ProbeTelegram(ctx context.Context, scope *brokercore.ProxyScope, service, rule, placeholder string) ProbeResult {
	transport := &http.Transport{
		DialContext:           netguard.TelegramDialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	return p.probeTelegram(ctx, scope, service, rule, placeholder, transport)
}

func (p *Proxy) probeTelegram(ctx context.Context, scope *brokercore.ProxyScope, service, rule, placeholder string, transport *http.Transport) (result ProbeResult) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	execution := &probeExecution{Service: service, Rule: rule, RequestID: evidence.ID()}
	ctx = context.WithValue(ctx, probeContextKey{}, execution)
	result = ProbeResult{Category: "unavailable", RequestID: execution.RequestID}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.telegram.org/bot"+placeholder+"/getMe", nil)
	if err != nil {
		return result
	}
	request.Body = http.NoBody
	response := &probeResponse{header: make(http.Header)}
	// Forward through the shared injection path without copying the listener's
	// atomic lifecycle state or writing diagnostic traffic to general logs.
	isolated := &Proxy{creds: p.creds, baseURL: p.baseURL, rateLimit: p.rateLimit,
		logger: slog.New(slog.DiscardHandler), logSink: requestlog.Nop{}, upstream: transport,
		maxResponseBytes: 65536, maxRequestBytes: 1024}

	defer func() {
		result.Loaded, result.Used = execution.Loaded, execution.Used
		if recovered := recover(); recovered != nil {
			if recovered != http.ErrAbortHandler {
				panic(recovered)
			}
			result.Category = "response_too_large"
		}
	}()
	isolated.forwardRequest(response, request, "api.telegram.org:443", "api.telegram.org", 443, true, scope)
	result.Loaded, result.Used = execution.Loaded, execution.Used
	if execution.Category != "" {
		result.Category = execution.Category
		return result
	}
	if response.overflow {
		result.Category = "response_too_large"
		return result
	}
	if ctx.Err() != nil {
		result.Category = "timeout"
		return result
	}
	switch {
	case response.status == http.StatusOK:
		var body struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(response.body.Bytes(), &body) == nil && body.OK {
			result.Category = "ok"
		} else {
			result.Category = "invalid_response"
		}
	case response.status == 401 || response.status == 403:
		result.Category = "rejected"
	case response.status >= 300 && response.status < 400:
		result.Category = "redirect_blocked"
	case response.status == 429:
		result.Category = "rate_limited"
	default:
		result.Category = "unavailable"
	}
	return result
}

func recordForwarded(ctx context.Context, inject *brokercore.InjectResult, scope *brokercore.ProxyScope) {
	actorType, actorID := actorFromScope(scope)
	kind, requestID := "recipient_ingress", evidence.ID()
	if probe, ok := ctx.Value(probeContextKey{}).(*probeExecution); ok {
		kind, requestID = "management_probe", probe.RequestID
		probe.Used = true
		probe.Loaded = inject.Loaded
	}
	evidence.Default.RecordUsed(inject.Loaded, kind, actorType, actorID, requestID)
}

var _ io.Writer = (*probeResponse)(nil)
