package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/evidence"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/store"
)

type diagnosticRequest struct {
	Version       int      `json:"version"`
	Operation     string   `json:"operation"`
	Service       string   `json:"service"`
	Keys          []string `json:"keys"`
	RecipientID   string   `json:"recipient_id"`
	RecipientType string   `json:"recipient_type"`
	OptIn         bool     `json:"opt_in"`
}

type diagnosticResponse struct {
	Version          int               `json:"version"`
	Vault            string            `json:"vault"`
	Service          string            `json:"service"`
	Keys             []string          `json:"keys"`
	Loaded           evidence.Result   `json:"loaded"`
	RecipientIngress evidence.Result   `json:"recipient_ingress"`
	ManagementProbe  *mitm.ProbeResult `json:"management_probe,omitempty"`
}

type diagnosticGuard struct {
	Management store.VaultGrant
	Recipient  store.VaultGrant
	Config     string
	Rule       string
}

func (s *Server) diagnosticGrant(ctx context.Context, actorID, actorType, vaultID string) (store.VaultGrant, error) {
	actor, err := s.actorByID(ctx, actorID, actorType)
	if err != nil || (actor.Agent != nil && actor.Agent.RevokedAt != nil) || (actor.User != nil && !actor.User.IsActive) {
		return store.VaultGrant{}, errors.New("actor unavailable")
	}
	grants, err := s.store.ListActorGrants(ctx, actorID)
	if err != nil {
		return store.VaultGrant{}, err
	}
	for _, grant := range grants {
		if grant.VaultID == vaultID && grant.ActorType == actorType {
			return grant, nil
		}
	}
	return store.VaultGrant{}, errors.New("membership unavailable")
}

func selectedDiagnosticService(snapshot *store.BrokerSnapshot, name string) (*broker.Service, error) {
	if snapshot == nil || snapshot.Config == nil {
		return nil, errors.New("rule unavailable")
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(snapshot.Config.ServicesJSON), &services); err != nil {
		return nil, err
	}
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	broker.AssignSlugNames(services)
	for index := range services {
		if services[index].Name == name && services[index].IsEnabled() {
			return &services[index], nil
		}
	}
	return nil, errors.New("rule unavailable")
}

func (s *Server) diagnosticState(ctx context.Context, actor *Actor, request diagnosticRequest, vaultID string) (diagnosticGuard, *store.BrokerSnapshot, *broker.Service, error) {
	var guard diagnosticGuard
	management, err := s.diagnosticGrant(ctx, actor.ID, actor.Type, vaultID)
	if err != nil || management.Role != "admin" || actor.Role == "no-access" {
		return guard, nil, nil, errors.New("management membership unavailable")
	}
	recipient, err := s.diagnosticGrant(ctx, request.RecipientID, request.RecipientType, vaultID)
	if err != nil {
		return guard, nil, nil, err
	}
	snapshot, err := (credentialStoreAdapter{s.store}).GetBrokerSnapshot(ctx, vaultID)
	if err != nil {
		return guard, nil, nil, err
	}
	service, err := selectedDiagnosticService(snapshot, request.Service)
	if err != nil {
		return guard, nil, nil, err
	}
	cs, err := s.store.GetVaultCredentialStore(ctx, vaultID)
	if err != nil || cs == nil || cs.Kind != store.CredentialStoreHashicorp {
		return guard, nil, nil, errors.New("source unavailable")
	}
	guard = diagnosticGuard{Management: management, Recipient: recipient, Config: evidence.Digest(cs.ConfigJSON), Rule: evidence.Digest(service)}
	return guard, snapshot, service, nil
}

var diagnosticPlaceholder = regexp.MustCompile(`^[A-Za-z0-9_~-]{1,128}$`)

func telegramPlaceholder(service *broker.Service) (string, bool) {
	if service.Host != "api.telegram.org" || (service.Port != nil && *service.Port != 443) || len(service.Substitutions) != 1 || service.Auth.Type != "passthrough" {
		return "", false
	}
	substitution := service.Substitutions[0]
	if !diagnosticPlaceholder.MatchString(substitution.Placeholder) || !slices.Equal(substitution.NormalizedIn(), []string{"path"}) {
		return "", false
	}
	matched, _ := broker.MatchService("api.telegram.org", 443, "/bot"+substitution.Placeholder+"/getMe", []broker.Service{*service})
	return substitution.Placeholder, matched != nil
}

func (s *Server) diagnosticLoaded(snapshot *store.BrokerSnapshot, service *broker.Service, vaultID string) (*evidence.Loaded, error) {
	loaded := &evidence.Loaded{Vault: vaultID, Service: service.Name, Rule: evidence.Digest(service), Fingerprints: make(map[string]evidence.Fingerprint), At: time.Now().UTC()}
	ciphertexts := make(map[string][2][]byte)
	keys := service.CredentialKeys()
	for _, credential := range snapshot.Credentials {
		ciphertexts[credential.Key] = [2][]byte{credential.Ciphertext, credential.Nonce}
		if !slices.Contains(keys, credential.Key) {
			continue
		}
		if credential.Type != "static" {
			return nil, errors.New("unsupported credential")
		}
		value, err := crypto.Decrypt(credential.Ciphertext, credential.Nonce, s.encKey)
		if err != nil {
			return nil, errors.New("credential unavailable")
		}
		loaded.Fingerprints[credential.Key] = evidence.Default.Fingerprint(string(value))
		crypto.WipeBytes(value)
	}
	if len(loaded.Fingerprints) != len(keys) {
		return nil, errors.New("credential unavailable")
	}
	loaded.SnapshotID = evidence.SnapshotID(ciphertexts)
	return loaded, nil
}

func (s *Server) handleDiagnostic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	vault := s.resolveVaultByPath(w, r)
	if vault == nil {
		return
	}
	actor, err := s.requireVaultAdmin(w, r, vault.ID)
	if err != nil {
		return
	}
	if actor == nil {
		jsonError(w, http.StatusForbidden, "Instance management identity required")
		return
	}
	var request diagnosticRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid diagnostic request")
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Version != 1 || request.Service == "" || len(request.Keys) == 0 || len(request.Keys) > 128 || request.RecipientID == "" || (request.RecipientType != "agent" && request.RecipientType != "user") || (request.Operation != "evidence" && request.Operation != "telegram_get_me") || (request.Operation == "telegram_get_me" && !request.OptIn) {
		jsonError(w, http.StatusBadRequest, "Unsupported diagnostic request")
		return
	}
	guard, snapshot, service, err := s.diagnosticState(r.Context(), actor, request, vault.ID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Diagnostic scope unavailable")
		return
	}
	keys := service.CredentialKeys()
	slices.Sort(keys)
	slices.Sort(request.Keys)
	if !slices.Equal(keys, request.Keys) {
		jsonError(w, http.StatusForbidden, "Exact service key set required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cs, err := s.store.GetVaultCredentialStore(ctx, vault.ID)
	copyAvailable := false
	var observedCopy evidence.Copy
	if err == nil && cs != nil && evidence.Digest(cs.ConfigJSON) == guard.Config && s.hashicorpSyncer != nil {
		observedCopy, err = s.hashicorpSyncer.ObserveCopy(ctx, *cs)
		copyAvailable = err == nil
	}
	loaded, loadErr := s.diagnosticLoaded(snapshot, service, vault.ID)
	response := diagnosticResponse{Version: 1, Vault: vault.Name, Service: service.Name, Keys: keys, Loaded: evidence.Result{State: "unavailable"}, RecipientIngress: evidence.Result{State: "not_checked"}}
	if loadErr == nil && copyAvailable {
		response.Loaded = evidence.Default.InspectObserved(loaded, guard.Config, observedCopy)
	}
	if request.Operation == "telegram_get_me" {
		placeholder, supported := telegramPlaceholder(service)
		probe := mitm.ProbeResult{Category: "unsupported"}
		if supported && loadErr == nil && copyAvailable && s.mitm != nil {
			scope := &brokercore.ProxyScope{VaultID: vault.ID, VaultName: vault.Name, VaultRole: "admin"}
			if actor.Type == "agent" {
				scope.AgentID = actor.ID
			} else {
				scope.UserID = actor.ID
			}
			probe = s.mitm.ProbeTelegram(ctx, scope, service.Name, guard.Rule, placeholder)
			if probe.Loaded != nil {
				response.Loaded = evidence.Default.InspectObserved(probe.Loaded, guard.Config, observedCopy)
				if probe.Used {
					observation := response.Loaded
					observation.UsedAt = probe.UsedAt
					observation.ActorKind, observation.ActorType, observation.ActorID, observation.RequestID = "management_probe", actor.Type, actor.ID, probe.RequestID
					probe.Evidence = &observation
				}
			}
		}
		response.ManagementProbe = &probe
	}
	if copyAvailable {
		response.RecipientIngress = evidence.Default.RecipientObserved(vault.ID, service.Name, guard.Rule, request.RecipientType, request.RecipientID, guard.Config, keys, observedCopy)
		if used := response.RecipientIngress.UsedAt; used != nil && used.Before(guard.Recipient.CreatedAt) {
			response.RecipientIngress = evidence.Result{State: "not_checked", Reason: "membership_changed"}
		}
	}
	after, _, _, err := s.diagnosticState(r.Context(), actor, request, vault.ID)
	if err != nil || evidence.Digest(after) != evidence.Digest(guard) {
		jsonError(w, http.StatusConflict, "Diagnostic scope changed")
		return
	}
	jsonOK(w, response)
}
