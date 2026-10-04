package store

import (
	"context"
	"database/sql"
	"errors"
)

type BrokerSnapshot struct {
	Config      *BrokerConfig
	Credentials []Credential
}

func (s *SQLStore) GetBrokerSnapshot(ctx context.Context, vaultID string) (*BrokerSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	snapshot := &BrokerSnapshot{}
	var services string
	err = tx.QueryRowContext(ctx, s.dialect.Rebind("SELECT services_json FROM broker_configs WHERE vault_id = ?"), vaultID).Scan(&services)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		snapshot.Config = &BrokerConfig{VaultID: vaultID, ServicesJSON: services}
	}
	rows, err := tx.QueryContext(ctx, s.dialect.Rebind("SELECT id, vault_id, key, type, ciphertext, nonce, created_at, updated_at FROM credentials WHERE vault_id = ? ORDER BY key"), vaultID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		credential, err := s.scanCredential(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		snapshot.Credentials = append(snapshot.Credentials, *credential)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}
