package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

const TTL = 5 * time.Minute
const capacity = 256
const maxFields = 256

// Fingerprint is private diagnostic data; never add it to catalogue or request logs.
type Fingerprint struct {
	SHA256    string `json:"sha256"`
	UTF8Bytes int    `json:"utf8_bytes"`
}

type Copy struct {
	Config       string
	Version      *int
	CreatedAt    time.Time
	ObservedAt   time.Time
	Fingerprints map[string]Fingerprint
}

type Loaded struct {
	Vault        string
	Service      string
	Rule         string
	SnapshotID   string
	Fingerprints map[string]Fingerprint
	At           time.Time
}

type Import struct {
	ID         string
	SnapshotID string
	Copy       Copy
	At         time.Time
}

type Used struct {
	Loaded    Loaded
	ActorKind string
	ActorType string
	ActorID   string
	RequestID string
	At        time.Time
}

type Result struct {
	State               string                 `json:"state"`
	Reason              string                 `json:"reason,omitempty"`
	Fields              map[string]Fingerprint `json:"fields,omitempty"`
	CopyFields          map[string]Fingerprint `json:"copy_fields,omitempty"`
	ImportedCopyVersion *int                   `json:"imported_copy_version,omitempty"`
	CopyVersion         *int                   `json:"copy_version"`
	CopyObservedAt      *time.Time             `json:"copy_observed_at,omitempty"`
	ImportID            string                 `json:"import_id,omitempty"`
	SnapshotID          string                 `json:"snapshot_id,omitempty"`
	LoadedAt            *time.Time             `json:"loaded_at,omitempty"`
	UsedAt              *time.Time             `json:"used_at,omitempty"`
	ActorKind           string                 `json:"actor_kind,omitempty"`
	ActorType           string                 `json:"actor_type,omitempty"`
	ActorID             string                 `json:"actor_id,omitempty"`
	RequestID           string                 `json:"request_id,omitempty"`
}

type Registry struct {
	mu      sync.Mutex
	imports map[string]Import
	copies  map[string]Copy
	uses    []Used
	clock   func() time.Time
}

func New() *Registry {
	registry := &Registry{imports: make(map[string]Import), copies: make(map[string]Copy), clock: time.Now}
	return registry
}

var Default = New()

func ID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes[:])
}

func Digest(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (r *Registry) Fingerprint(value string) Fingerprint {
	sum := sha256.Sum256([]byte(value))
	return Fingerprint{SHA256: hex.EncodeToString(sum[:]), UTF8Bytes: len(value)}
}

func cloneCopy(copy Copy) Copy {
	cloned := make(map[string]Fingerprint, len(copy.Fingerprints))
	for key, value := range copy.Fingerprints {
		cloned[key] = value
	}
	copy.Fingerprints = cloned
	if copy.Version != nil {
		version := *copy.Version
		copy.Version = &version
	}
	return copy
}

func (r *Registry) prune() {
	now := r.clock()
	for key, imported := range r.imports {
		if now.Sub(imported.At) >= TTL {
			delete(r.imports, key)
		}
	}
	for key, copy := range r.copies {
		if now.Sub(copy.ObservedAt) >= TTL {
			delete(r.copies, key)
		}
	}
	remaining := r.uses[:0]
	for _, used := range r.uses {
		if now.Sub(used.At) < TTL {
			remaining = append(remaining, used)
		}
	}
	r.uses = remaining
}

func (r *Registry) Observe(vault string, copy Copy) {
	if len(copy.Fingerprints) > maxFields {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if len(r.copies) >= capacity {
		r.copies = make(map[string]Copy)
	}
	r.copies[vault] = cloneCopy(copy)
}

func (r *Registry) Applied(vault, version string, copy Copy) {
	if len(copy.Fingerprints) > maxFields {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if len(r.imports) >= capacity {
		r.imports = make(map[string]Import)
	}
	r.imports[vault+":"+version] = Import{ID: ID(), SnapshotID: version, Copy: cloneCopy(copy), At: r.clock().UTC()}
}

func (r *Registry) RecordUsed(loaded *Loaded, kind, actorType, actorID, requestID string) {
	if loaded == nil || actorID == "" || len(loaded.Fingerprints) > maxFields {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if len(r.uses) >= capacity {
		r.uses = r.uses[1:]
	}
	copy := *loaded
	copy.Fingerprints = cloneCopy(Copy{Fingerprints: loaded.Fingerprints}).Fingerprints
	r.uses = append(r.uses, Used{Loaded: copy, ActorKind: kind, ActorType: actorType, ActorID: actorID, RequestID: requestID, At: r.clock().UTC()})
}

func sameKeys(fingerprints map[string]Fingerprint, keys []string) bool {
	if len(fingerprints) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := fingerprints[key]; !ok {
			return false
		}
	}
	return true
}

func (r *Registry) inspect(loaded *Loaded, config string, observed *Copy) Result {
	result := Result{State: "unavailable", Reason: "snapshot_provenance_unavailable"}
	if loaded == nil {
		return result
	}
	result.Fields = cloneCopy(Copy{Fingerprints: loaded.Fingerprints}).Fingerprints
	result.SnapshotID = loaded.SnapshotID
	result.LoadedAt = &loaded.At
	copy, ok := r.copies[loaded.Vault]
	if observed != nil {
		copy, ok = *observed, true
	}
	if !ok || copy.Config != config {
		return result
	}
	result.CopyFields = make(map[string]Fingerprint)
	for key := range loaded.Fingerprints {
		if field, ok := copy.Fingerprints[key]; ok {
			result.CopyFields[key] = field
		}
	}
	result.CopyVersion = copy.Version
	result.CopyObservedAt = &copy.ObservedAt
	imported, ok := r.imports[loaded.Vault+":"+loaded.SnapshotID]
	if !ok || imported.Copy.Config != config {
		return result
	}
	result.ImportID = imported.ID
	result.ImportedCopyVersion = imported.Copy.Version
	result.Reason = ""
	result.State = "matched"
	for key, hash := range loaded.Fingerprints {
		if copy.Fingerprints[key] != hash || imported.Copy.Fingerprints[key] != hash {
			result.State = "mismatch"
			return result
		}
	}
	if r.clock().Sub(loaded.At) >= TTL {
		result.State, result.Reason = "not_checked", "stale_snapshot"
	}
	if imported.Copy.Version != nil && copy.Version != nil && *imported.Copy.Version != *copy.Version {
		result.State, result.Reason = "not_checked", "stale_snapshot"
	}
	return result
}

func (r *Registry) Inspect(loaded *Loaded, config string) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	return r.inspect(loaded, config, nil)
}

func (r *Registry) InspectObserved(loaded *Loaded, config string, observed Copy) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	return r.inspect(loaded, config, &observed)
}

func (r *Registry) Recipient(vault, service, rule, actorType, actorID, config string, keys []string) Result {
	return r.recipient(vault, service, rule, actorType, actorID, config, keys, nil)
}

func (r *Registry) RecipientObserved(vault, service, rule, actorType, actorID, config string, keys []string, observed Copy) Result {
	return r.recipient(vault, service, rule, actorType, actorID, config, keys, &observed)
}

func (r *Registry) recipient(vault, service, rule, actorType, actorID, config string, keys []string, observed *Copy) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	for index := len(r.uses) - 1; index >= 0; index-- {
		used := r.uses[index]
		if used.ActorKind != "recipient_ingress" || used.ActorID != actorID || used.ActorType != actorType || used.Loaded.Vault != vault || used.Loaded.Service != service || used.Loaded.Rule != rule || !sameKeys(used.Loaded.Fingerprints, keys) {
			continue
		}
		result := r.inspect(&used.Loaded, config, observed)
		result.UsedAt = &used.At
		result.ActorKind = used.ActorKind
		result.ActorType = used.ActorType
		result.ActorID = used.ActorID
		result.RequestID = used.RequestID
		return result
	}
	return Result{State: "not_checked"}
}

func SnapshotID(items map[string][2][]byte) string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]any, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, []any{key, items[key]})
	}
	return Digest(ordered)
}
