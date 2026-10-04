package evidence

import (
	"strings"
	"testing"
	"time"
)

func TestPrivateSnapshotEvidence(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	r.clock = func() time.Time { return now }
	version := 7
	fields := map[string]Fingerprint{"TOKEN": r.Fingerprint("привет")}
	if fields["TOKEN"].UTF8Bytes != 12 {
		t.Fatal("UTF-8 byte count")
	}
	copy := Copy{Config: "cfg", Version: &version, ObservedAt: now, Fingerprints: fields}
	loaded := &Loaded{Vault: "v", Service: "s", Rule: "rule", SnapshotID: "snapshot-2", Fingerprints: fields, At: now}
	r.Observe("v", copy)
	if got := r.Inspect(loaded, "cfg"); got.State != "unavailable" || len(got.Fields) != 1 {
		t.Fatalf("unproven import: %+v", got)
	}
	r.Applied("v", loaded.SnapshotID, copy)
	if got := r.Inspect(loaded, "cfg"); got.State != "matched" || got.ImportID == "" || *got.CopyVersion != 7 {
		t.Fatalf("matching values with independent version: %+v", got)
	}
	r.RecordUsed(loaded, "management_probe", "agent", "management", "req1")
	if got := r.Recipient("v", "s", "rule", "agent", "recipient", "cfg", []string{"TOKEN"}); got.State != "not_checked" {
		t.Fatal("management probe became recipient ingress")
	}
	r.RecordUsed(loaded, "recipient_ingress", "agent", "recipient", "req2")
	if got := r.Recipient("v", "s", "rule", "agent", "recipient", "cfg", []string{"TOKEN"}); got.State != "matched" || got.RequestID != "req2" {
		t.Fatalf("missing authenticated use: %+v", got)
	}
	if got := r.Recipient("v", "s", "other-rule", "agent", "recipient", "cfg", []string{"TOKEN"}); got.State != "not_checked" {
		t.Fatal("rule isolation")
	}
	rotated := copy
	rotated.Fingerprints = map[string]Fingerprint{"TOKEN": r.Fingerprint("приве")}
	r.Observe("v", copy)
	if got := r.InspectObserved(loaded, "cfg", rotated); got.State != "mismatch" {
		t.Fatal("concurrent global observation replaced this request snapshot")
	}
	r.Observe("v", rotated)
	if got := r.Inspect(loaded, "cfg"); got.State != "mismatch" {
		t.Fatal("lost character not detected")
	}
	r.Observe("v", copy)
	nextVersion := 8
	copy.Version = &nextVersion
	r.Observe("v", copy)
	if got := r.Inspect(loaded, "cfg"); got.State != "not_checked" || got.Reason != "stale_snapshot" {
		t.Fatal("old source version accepted")
	}
	if got := r.Inspect(loaded, "changed-config"); got.State != "unavailable" {
		t.Fatal("config isolation")
	}
	now = now.Add(TTL)
	if got := r.Recipient("v", "s", "rule", "agent", "recipient", "cfg", []string{"TOKEN"}); got.State != "not_checked" {
		t.Fatal("expired evidence")
	}
}

func TestSnapshotIdentityAndCapacity(t *testing.T) {
	a := map[string][2][]byte{"A": {[]byte("one"), []byte("nonce")}, "B": {[]byte("two"), []byte("nonce2")}}
	b := map[string][2][]byte{"B": a["B"], "A": a["A"]}
	if SnapshotID(a) != SnapshotID(b) {
		t.Fatal("nondeterministic snapshot")
	}
	b["A"] = [2][]byte{[]byte("new"), []byte("nonce")}
	if SnapshotID(a) == SnapshotID(b) {
		t.Fatal("rotation not bound")
	}
	r := New()
	now := time.Now()
	for i := 0; i < capacity+10; i++ {
		r.Observe(ID(), Copy{ObservedAt: now})
		r.Applied(ID(), "v", Copy{})
		r.RecordUsed(&Loaded{}, "recipient_ingress", "agent", "a", ID())
	}
	if len(r.copies) > capacity || len(r.imports) > capacity || len(r.uses) > capacity {
		t.Fatal("unbounded evidence")
	}
	if strings.Contains(r.Fingerprint("secret-value").SHA256, "secret-value") {
		t.Fatal("plaintext fingerprint")
	}
}
