package store

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestBrokerSnapshotDoesNotMixRotations(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	v, err := s.CreateVault(ctx, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetBrokerConfig(ctx, v.ID, `[]`); err != nil {
		t.Fatal(err)
	}
	write := func(n int) error {
		value := []byte(fmt.Sprint(n))
		_, e := s.SetVaultExternalStore(ctx, SetVaultExternalStoreParams{VaultID: v.ID, Kind: CredentialStoreHashicorp, ConfigJSON: `{"mount":"secret","secret_path":"test","kv_version":2}`, PollIntervalSeconds: 60, Credentials: []EncryptedKV{{Key: "A", Ciphertext: value, Nonce: []byte("n")}, {Key: "B", Ciphertext: value, Nonce: []byte("n")}}})
		return e
	}
	if err = write(0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 1; n < 150; n++ {
			if e := write(n); e != nil {
				t.Error(e)
				return
			}
		}
	}()
	for n := 0; n < 150; n++ {
		snapshot, e := s.GetBrokerSnapshot(ctx, v.ID)
		if e != nil {
			t.Fatal(e)
		}
		if snapshot.Config == nil || len(snapshot.Credentials) != 2 || !bytes.Equal(snapshot.Credentials[0].Ciphertext, snapshot.Credentials[1].Ciphertext) {
			t.Fatal("mixed credential generations")
		}
	}
	wg.Wait()
}
