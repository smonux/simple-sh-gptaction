package auth

import (
	"database/sql"
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
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := initSQLiteSchema(db); err != nil {
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func initSQLiteSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS oauth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			scope TEXT,
			expires_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS oauth_codes_expires ON oauth_codes(expires_at);`,
		`CREATE TABLE IF NOT EXISTS oauth_tokens (
			token TEXT PRIMARY KEY,
			scope TEXT,
			expires_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS oauth_tokens_expires ON oauth_tokens(expires_at);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) issueToken(ttl time.Duration, scope string) (issuedToken, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	expiresAt := time.Now().Add(ttl).Unix()
	for i := 0; i < 5; i++ {
		token := randomToken()
		_, err := s.db.Exec(`INSERT INTO oauth_tokens (token, scope, expires_at) VALUES (?, ?, ?)`, token, scope, expiresAt)
		if err == nil {
			return issuedToken{Value: token, TTL: ttl}, nil
		}
		if !isUniqueViolation(err) {
			return issuedToken{}, err
		}
	}
	return issuedToken{}, fmt.Errorf("failed to issue unique token")
}

func (s *sqliteStore) validateToken(token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	now := time.Now().Unix()
	_, _ = s.db.Exec(`DELETE FROM oauth_tokens WHERE expires_at <= ?`, now)
	var expiresAt int64
	err := s.db.QueryRow(`SELECT expires_at FROM oauth_tokens WHERE token = ?`, token).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if now >= expiresAt {
		_, _ = s.db.Exec(`DELETE FROM oauth_tokens WHERE token = ?`, token)
		return false, nil
	}
	return true, nil
}

func (s *sqliteStore) issueCode(ttl time.Duration, info codeInfo) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	expiresAt := time.Now().Add(ttl).Unix()
	for i := 0; i < 5; i++ {
		code := randomToken()
		_, err := s.db.Exec(
			`INSERT INTO oauth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			code, info.clientID, info.redirectURI, info.codeChallenge, info.codeChallengeMethod, info.scope, expiresAt,
		)
		if err == nil {
			return code, nil
		}
		if !isUniqueViolation(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("failed to issue unique code")
}

func (s *sqliteStore) consumeCode(code, clientID, redirectURI, verifier string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("code is required")
	}
	now := time.Now().Unix()
	_, _ = s.db.Exec(`DELETE FROM oauth_codes WHERE expires_at <= ?`, now)
	var info codeInfo
	var expiresAt int64
	err := s.db.QueryRow(
		`SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at
		 FROM oauth_codes WHERE code = ?`, code,
	).Scan(&info.clientID, &info.redirectURI, &info.codeChallenge, &info.codeChallengeMethod, &info.scope, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("invalid code")
	}
	if err != nil {
		return "", err
	}
	_, _ = s.db.Exec(`DELETE FROM oauth_codes WHERE code = ?`, code)
	if now >= expiresAt {
		return "", fmt.Errorf("code expired")
	}
	if !subtleCompare(info.clientID, clientID) {
		return "", fmt.Errorf("invalid client_id")
	}
	if !subtleCompare(info.redirectURI, redirectURI) {
		return "", fmt.Errorf("invalid redirect_uri")
	}
	if verifier == "" {
		return "", fmt.Errorf("code_verifier is required")
	}
	if !verifyPKCE(info.codeChallengeMethod, info.codeChallenge, verifier) {
		return "", fmt.Errorf("invalid code_verifier")
	}
	return info.scope, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique")
}
