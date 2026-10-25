package auth

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func requestRefresh(o *OAuthServer, token string, extra url.Values) *httptest.ResponseRecorder {
	values := url.Values{"grant_type": {"refresh_token"}, "client_id": {"chatgpt_mcp"}, "refresh_token": {token}}
	for key, value := range extra {
		values[key] = value
	}
	r := httptest.NewRequest("POST", testResource+"/oauth/token", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	o.HandleToken(w, r)
	return w
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

func decodePair(t *testing.T, w *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("token request failed: status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response may be cached")
	}
	var pair tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.ExpiresIn <= 0 || pair.RefreshExpiresIn <= 0 {
		t.Fatal("incomplete token pair")
	}
	return pair
}

func TestRefreshAfterAccessExpiryAndReplayRevokesOnlyItsFamily(t *testing.T) {
	a, store := localOAuth(t)
	pair := decodePair(t, exchange(a.oauth, login(t, a.oauth, authorizeValues()), testVerifier, testResource))
	other, err := store.issueTokenPair(time.Hour, 24*time.Hour, "tools.execute", "chatgpt_mcp", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE oauth_tokens_v2 SET expires_at = 0 WHERE token_hash = ?`, credentialHash(pair.AccessToken)); err != nil {
		t.Fatal(err)
	}
	if a.oauth.Validate(pair.AccessToken) {
		t.Fatal("expired access token accepted")
	}
	// No resource parameter: keep the original audience, as MCP clients may do.
	renewed := decodePair(t, requestRefresh(a.oauth, pair.RefreshToken, nil))
	if renewed.AccessToken == pair.AccessToken || renewed.RefreshToken == pair.RefreshToken {
		t.Fatal("credentials were not rotated")
	}
	if renewed.Scope != "tools.execute" || !a.oauth.Validate(renewed.AccessToken, "tools.execute") {
		t.Fatal("renewed grant is not usable")
	}
	if renewed.RefreshExpiresIn > pair.RefreshExpiresIn {
		t.Fatal("rotation extended absolute grant lifetime")
	}
	var stored string
	if err := store.db.QueryRow(`SELECT token_hash FROM oauth_refresh_tokens WHERE consumed = 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != credentialHash(pair.RefreshToken) {
		t.Fatal("refresh token was not stored as a hash")
	}
	if w := requestRefresh(a.oauth, pair.RefreshToken, nil); w.Code != 400 {
		t.Fatal("used refresh token was accepted")
	}
	if a.oauth.Validate(renewed.AccessToken) {
		t.Fatal("replay did not revoke descendant access token")
	}
	if w := requestRefresh(a.oauth, renewed.RefreshToken, nil); w.Code != 400 {
		t.Fatal("replay did not revoke descendant refresh token")
	}
	if !a.oauth.Validate(other.Value) {
		t.Fatal("replay revoked an unrelated grant")
	}
}

func TestRefreshClientResourceIssuerAndScopeBinding(t *testing.T) {
	a, store := localOAuth(t)
	pair, err := store.issueTokenPair(time.Hour, 24*time.Hour, "tools.read tools.execute", "chatgpt_mcp", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		extra  url.Values
		status int
		code   string
	}{
		{"client", url.Values{"client_id": {"other-client"}}, 401, "invalid_client"},
		{"resource", url.Values{"resource": {"https://other.example"}}, 400, "invalid_target"},
		{"unknown scope", url.Values{"scope": {"admin"}}, 400, "invalid_scope"},
	} {
		w := requestRefresh(a.oauth, pair.RefreshToken, tc.extra)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Fatalf("%s accepted or wrong error: %d", tc.name, w.Code)
		}
	}
	if _, err := store.rotateRefreshToken(time.Hour, pair.RefreshToken, "chatgpt_mcp", testResource, "https://other.example", ""); !errors.Is(err, errRefreshInvalid) {
		t.Fatal("wrong issuer accepted")
	}
	narrowed := decodePair(t, requestRefresh(a.oauth, pair.RefreshToken, url.Values{"resource": {testResource + "/"}, "scope": {"tools.read"}}))
	if narrowed.Scope != "tools.read" || a.oauth.Validate(narrowed.AccessToken, "tools.execute") {
		t.Fatal("scope narrowing was not enforced")
	}
	if w := requestRefresh(a.oauth, narrowed.RefreshToken, url.Values{"scope": {"tools.execute"}}); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatal("scope escalation accepted")
	}
	// A rejected scope change does not consume the valid credential.
	preserved := decodePair(t, requestRefresh(a.oauth, narrowed.RefreshToken, nil))
	if preserved.Scope != "tools.read" {
		t.Fatal("narrowed permission was restored during rotation")
	}
	if w := requestRefresh(a.oauth, "", nil); w.Code != 400 {
		t.Fatal("missing refresh token accepted")
	}
	if w := requestRefresh(a.oauth, "unknown-credential", nil); w.Code != 400 {
		t.Fatal("random refresh token accepted")
	}
}

func TestRefreshPersistenceExpiryAndConcurrentReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.sqlite")
	store, err := newSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := store.issueToken(time.Hour, "tools.execute", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.issueTokenPair(time.Hour, 24*time.Hour, "tools.execute", "chatgpt_mcp", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = newSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if ok, err := store.validateToken(legacy.Value, testResource, testResource, nil); err != nil || !ok {
		t.Fatal("schema update invalidated a pre-refresh access token", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.rotateRefreshToken(time.Hour, pair.RefreshToken, "chatgpt_mcp", testResource, testResource, "")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, reused := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, errRefreshReused) {
			reused++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || reused != 1 {
		t.Fatalf("concurrent exchanges: success=%d replay=%d", success, reused)
	}
	pair, err = store.issueTokenPair(time.Hour, 24*time.Hour, "tools.execute", "chatgpt_mcp", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE oauth_refresh_families SET expires_at = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.rotateRefreshToken(time.Hour, pair.RefreshToken, "chatgpt_mcp", testResource, testResource, ""); !errors.Is(err, errRefreshInvalid) {
		t.Fatal("expired family accepted")
	}
	if ok, err := store.validateToken(pair.Value, testResource, testResource, nil); err != nil || ok {
		t.Fatal("access to expired family accepted", err)
	}
	// Cleanup must not turn expired family access tokens into unbound tokens.
	if _, err := store.issueTokenPair(time.Hour, 24*time.Hour, "tools.execute", "chatgpt_mcp", testResource, testResource); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.validateToken(pair.Value, testResource, testResource, nil); err != nil || ok {
		t.Fatal("cleanup resurrected access token", err)
	}
}
