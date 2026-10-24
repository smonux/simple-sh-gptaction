package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type sqliteStore struct {
	db *sql.DB
}

func newSQLiteStore(path string) (*sqliteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := initSQLiteSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func initSQLiteSchema(db *sql.DB) error {
	// v2 deliberately rejects old credentials without resource/issuer binding.
	// Old tables remain untouched so the database can still be rolled back.
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS oauth_codes_v2 (
			code_hash TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			resource TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS oauth_codes_v2_expires ON oauth_codes_v2(expires_at)`,
		`CREATE TABLE IF NOT EXISTS oauth_tokens_v2 (
			token_hash TEXT PRIMARY KEY,
			resource TEXT NOT NULL,
			issuer TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS oauth_tokens_v2_expires ON oauth_tokens_v2(expires_at)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func credentialHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *sqliteStore) issueToken(ttl time.Duration, scope, resource, issuer string) (issuedToken, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	token := randomToken()
	_, err := s.db.Exec(`INSERT INTO oauth_tokens_v2 (token_hash, resource, issuer, scope, expires_at) VALUES (?, ?, ?, ?, ?)`,
		credentialHash(token), resource, issuer, scope, time.Now().Add(ttl).Unix())
	if err != nil {
		return issuedToken{}, err
	}
	return issuedToken{Value: token, TTL: ttl}, nil
}

func (s *sqliteStore) validateToken(token, resource, issuer string, scopes []string) (bool, error) {
	if token == "" {
		return false, nil
	}
	now := time.Now().Unix()
	_, _ = s.db.Exec(`DELETE FROM oauth_tokens_v2 WHERE expires_at <= ?`, now)
	var storedResource, storedIssuer, scope string
	var expiresAt int64
	err := s.db.QueryRow(`SELECT resource, issuer, scope, expires_at FROM oauth_tokens_v2 WHERE token_hash = ?`,
		credentialHash(token)).Scan(&storedResource, &storedIssuer, &scope, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if now >= expiresAt || storedResource != resource || storedIssuer != issuer {
		return false, nil
	}
	granted := strings.Fields(scope)
	for _, required := range scopes {
		found := false
		for _, candidate := range granted {
			if candidate == required {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

func (s *sqliteStore) issueCode(ttl time.Duration, info codeInfo) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	code := randomToken()
	_, err := s.db.Exec(`INSERT INTO oauth_codes_v2 (code_hash, client_id, redirect_uri, code_challenge, resource, scope, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, credentialHash(code), info.clientID, info.redirectURI,
		info.codeChallenge, info.resource, info.scope, time.Now().Add(ttl).Unix())
	if err != nil {
		return "", err
	}
	return code, nil
}

func (s *sqliteStore) consumeCode(code, clientID, redirectURI, verifier, resource string) (string, error) {
	_, _ = s.db.Exec(`DELETE FROM oauth_codes_v2 WHERE expires_at <= ?`, time.Now().Unix())
	var info codeInfo
	var expiresAt int64
	// Atomic consumption prevents concurrent exchanges of the same code.
	// A failed exchange also burns the code.
	err := s.db.QueryRow(`DELETE FROM oauth_codes_v2 WHERE code_hash = ?
		RETURNING client_id, redirect_uri, code_challenge, resource, scope, expires_at`,
		credentialHash(code)).Scan(&info.clientID, &info.redirectURI, &info.codeChallenge,
		&info.resource, &info.scope, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("invalid or expired code")
	}
	if err != nil {
		return "", err
	}
	if time.Now().Unix() >= expiresAt || info.clientID != clientID || info.redirectURI != redirectURI ||
		info.resource != resource || !verifyPKCE("S256", info.codeChallenge, verifier) {
		return "", fmt.Errorf("invalid authorization grant")
	}
	return info.scope, nil
}
