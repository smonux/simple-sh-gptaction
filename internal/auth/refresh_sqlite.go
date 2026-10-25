package auth

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	errRefreshInvalid = errors.New("invalid refresh grant")
	errRefreshReused  = errors.New("refresh token reused")
	errRefreshScope   = errors.New("refresh scope exceeds grant")
)

func (s *sqliteStore) issueTokenPair(accessTTL, refreshTTL time.Duration, scope, clientID, resource, issuer string) (issuedTokenPair, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return issuedTokenPair{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	// Expired families cannot be refreshed. Remove their access tokens before
	// deleting the relationship, so no token can become an unbound legacy token.
	if _, err := tx.Exec(`DELETE FROM oauth_tokens_v2 WHERE token_hash IN (
		SELECT a.token_hash FROM oauth_refresh_access a JOIN oauth_refresh_families f USING (family_id)
		WHERE f.expires_at <= ?)`, now); err != nil {
		return issuedTokenPair{}, err
	}
	if _, err := tx.Exec(`DELETE FROM oauth_refresh_families WHERE expires_at <= ?`, now); err != nil {
		return issuedTokenPair{}, err
	}
	family := randomToken()
	expires := time.Now().Add(refreshTTL).Unix()
	_, err = tx.Exec(`INSERT INTO oauth_refresh_families (family_id, client_id, resource, issuer, expires_at) VALUES (?, ?, ?, ?, ?)`, family, clientID, resource, issuer, expires)
	if err != nil {
		return issuedTokenPair{}, err
	}
	pair, err := insertTokenPair(tx, accessTTL, scope, family, resource, issuer, expires)
	if err != nil {
		return issuedTokenPair{}, err
	}
	if err := tx.Commit(); err != nil {
		return issuedTokenPair{}, err
	}
	return pair, nil
}

func (s *sqliteStore) rotateRefreshToken(accessTTL time.Duration, token, clientID, resource, issuer, scope string) (issuedTokenPair, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return issuedTokenPair{}, err
	}
	defer tx.Rollback()
	var family, storedClient, storedResource, storedIssuer, grantedScope string
	var expires int64
	var consumed, revoked int
	err = tx.QueryRow(`SELECT t.family_id, t.scope, t.consumed, f.client_id, f.resource, f.issuer, f.expires_at, f.revoked
		FROM oauth_refresh_tokens t JOIN oauth_refresh_families f USING (family_id)
		WHERE t.token_hash = ?`, credentialHash(token)).Scan(&family, &grantedScope, &consumed, &storedClient, &storedResource, &storedIssuer, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return issuedTokenPair{}, errRefreshInvalid
	}
	if err != nil {
		return issuedTokenPair{}, err
	}
	if revoked != 0 || expires <= time.Now().Unix() || clientID != storedClient || resource != storedResource || issuer != storedIssuer {
		return issuedTokenPair{}, errRefreshInvalid
	}
	if consumed != 0 {
		// Keep used token hashes until expiry as replay-detection tombstones.
		// Revoke all descendants and access tokens from this grant atomically.
		if _, err := tx.Exec(`UPDATE oauth_refresh_families SET revoked = 1 WHERE family_id = ?`, family); err != nil {
			return issuedTokenPair{}, err
		}
		if _, err := tx.Exec(`DELETE FROM oauth_tokens_v2 WHERE token_hash IN (SELECT token_hash FROM oauth_refresh_access WHERE family_id = ?)`, family); err != nil {
			return issuedTokenPair{}, err
		}
		if err := tx.Commit(); err != nil {
			return issuedTokenPair{}, err
		}
		return issuedTokenPair{}, errRefreshReused
	}
	if scope == "" {
		scope = grantedScope
	}
	if !scopeSubset(scope, grantedScope) {
		return issuedTokenPair{}, errRefreshScope
	}
	result, err := tx.Exec(`UPDATE oauth_refresh_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0`, credentialHash(token))
	if err != nil {
		return issuedTokenPair{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return issuedTokenPair{}, err
	}
	if count != 1 {
		return issuedTokenPair{}, errRefreshInvalid
	}
	pair, err := insertTokenPair(tx, accessTTL, scope, family, resource, issuer, expires)
	if err != nil {
		return issuedTokenPair{}, err
	}
	if err := tx.Commit(); err != nil {
		return issuedTokenPair{}, err
	}
	return pair, nil
}

func insertTokenPair(tx *sql.Tx, accessTTL time.Duration, scope, family, resource, issuer string, refreshExpires int64) (issuedTokenPair, error) {
	now := time.Now().Unix()
	remaining := time.Duration(refreshExpires-now) * time.Second
	if remaining <= 0 {
		return issuedTokenPair{}, errRefreshInvalid
	}
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	if accessTTL > remaining {
		accessTTL = remaining
	}
	pair := issuedTokenPair{
		issuedToken:  issuedToken{Value: randomToken(), TTL: accessTTL},
		RefreshToken: randomToken(), RefreshTTL: remaining, Scope: scope,
	}
	accessHash := credentialHash(pair.Value)
	if _, err := tx.Exec(`INSERT INTO oauth_tokens_v2 (token_hash, resource, issuer, scope, expires_at) VALUES (?, ?, ?, ?, ?)`, accessHash, resource, issuer, scope, now+int64(accessTTL/time.Second)); err != nil {
		return issuedTokenPair{}, err
	}
	if _, err := tx.Exec(`INSERT INTO oauth_refresh_access (token_hash, family_id) VALUES (?, ?)`, accessHash, family); err != nil {
		return issuedTokenPair{}, err
	}
	if _, err := tx.Exec(`INSERT INTO oauth_refresh_tokens (token_hash, family_id, scope) VALUES (?, ?, ?)`, credentialHash(pair.RefreshToken), family, scope); err != nil {
		return issuedTokenPair{}, err
	}
	return pair, nil
}

func scopeSubset(requested, granted string) bool {
	allowed := make(map[string]bool)
	for _, scope := range strings.Fields(granted) {
		allowed[scope] = true
	}
	for _, scope := range strings.Fields(requested) {
		if !allowed[scope] {
			return false
		}
	}
	return true
}
