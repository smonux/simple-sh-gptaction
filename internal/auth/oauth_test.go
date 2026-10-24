package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const testResource = "https://mcp.example.com"
const testRedirect = "https://chatgpt.com/connector_platform_oauth_redirect"
const testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func localOAuth(t *testing.T) (*Authorizer, *sqliteStore) {
	t.Helper()
	a, err := NewAuthorizer(Config{
		Mode: "oauth", OAuthClientID: "chatgpt_mcp", OAuthUsername: "owner",
		OAuthPassword: " local password ", PublicURL: testResource,
		OAuthRedirectURIs: []string{testRedirect}, OAuthSQLitePath: filepath.Join(t.TempDir(), "oauth.sqlite"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := a.oauth.tokens.(*sqliteStore)
	t.Cleanup(func() { _ = s.db.Close() })
	return a, s
}

func authorizeValues() url.Values {
	sum := sha256.Sum256([]byte(testVerifier))
	return url.Values{
		"client_id": {"chatgpt_mcp"}, "response_type": {"code"}, "redirect_uri": {testRedirect},
		"resource": {testResource}, "scope": {"tools.execute"}, "state": {"state-to-preserve"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
}

func login(t *testing.T, o *OAuthServer, values url.Values) string {
	t.Helper()
	w := httptest.NewRecorder()
	o.HandleAuthorize(w, httptest.NewRequest("GET", testResource+"/oauth/authorize?"+values.Encode(), nil))
	if w.Code != 200 {
		t.Fatalf("login GET: %d %s", w.Code, w.Body)
	}
	csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(csrf) != 2 {
		t.Fatal("missing CSRF token")
	}
	values.Set("csrf_token", csrf[1])
	values.Set("username", "owner")
	values.Set("password", " local password ")
	r := httptest.NewRequest("POST", testResource+"/oauth/authorize", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	o.HandleAuthorize(w, r)
	if w.Code != 302 {
		t.Fatalf("login POST: %d %s", w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != "state-to-preserve" || u.Query().Get("iss") != testResource {
		t.Fatalf("state or issuer missing: %s", u)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", u)
	}
	return code
}

func exchange(o *OAuthServer, code, verifier, resource string) *httptest.ResponseRecorder {
	values := url.Values{
		"client_id": {"chatgpt_mcp"}, "grant_type": {"authorization_code"},
		"code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}, "resource": {resource},
	}
	r := httptest.NewRequest("POST", testResource+"/oauth/token", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	o.HandleToken(w, r)
	return w
}

func TestLocalLoginPKCEAndTokenAuthorization(t *testing.T) {
	a, store := localOAuth(t)
	code := login(t, a.oauth, authorizeValues())
	w := exchange(a.oauth, code, testVerifier, testResource)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || token.AccessToken == "" {
		t.Fatalf("token exchange: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("POST", testResource+"/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if !a.AuthorizeRequest(r, "tools.execute") {
		t.Fatal("valid token denied")
	}
	if a.AuthorizeRequest(r, "tools.read") {
		t.Fatal("missing scope accepted")
	}
	if ok, err := store.validateToken(token.AccessToken, "https://other.example", testResource, nil); err != nil || ok {
		t.Fatal("wrong resource accepted", err)
	}
	if ok, err := store.validateToken(token.AccessToken, testResource, "https://other.example", nil); err != nil || ok {
		t.Fatal("wrong issuer accepted", err)
	}
	var stored string
	if err := store.db.QueryRow(`SELECT token_hash FROM oauth_tokens_v2`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token.AccessToken || stored != credentialHash(token.AccessToken) {
		t.Fatal("token not hashed")
	}
	if w := exchange(a.oauth, code, testVerifier, testResource); w.Code != 400 {
		t.Fatal("code reused")
	}
	if _, err := store.db.Exec(`UPDATE oauth_tokens_v2 SET expires_at = 0`); err != nil {
		t.Fatal(err)
	}
	if a.AuthorizeRequest(r) {
		t.Fatal("expired token accepted")
	}
}

func TestRejectInvalidAuthorization(t *testing.T) {
	a, _ := localOAuth(t)
	for _, tc := range []struct{ key, value, errorCode string }{
		{"code_challenge_method", "plain", "invalid_request"},
		{"code_challenge_method", "", "invalid_request"},
		{"resource", "https://other.example", "invalid_target"},
		{"scope", "admin", "invalid_scope"},
		{"client_id", "unknown", "unauthorized_client"},
	} {
		values := authorizeValues()
		values.Set(tc.key, tc.value)
		w := httptest.NewRecorder()
		a.oauth.HandleAuthorize(w, httptest.NewRequest("GET", testResource+"/oauth/authorize?"+values.Encode(), nil))
		u, _ := url.Parse(w.Header().Get("Location"))
		if u.Query().Get("error") != tc.errorCode || u.Query().Get("iss") != testResource {
			t.Fatalf("%s: %d %s", tc.key, w.Code, w.Header())
		}
	}
	values := authorizeValues()
	values.Set("redirect_uri", "https://attacker.example/callback")
	w := httptest.NewRecorder()
	a.oauth.HandleAuthorize(w, httptest.NewRequest("GET", testResource+"/oauth/authorize?"+values.Encode(), nil))
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("redirect outside allowlist accepted")
	}
	values = authorizeValues()
	values.Set("username", "owner")
	values.Set("password", " local password ")
	r := httptest.NewRequest("POST", testResource+"/oauth/authorize", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	a.oauth.HandleAuthorize(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", w.Code)
	}
}

func TestRejectWrongVerifierAndResource(t *testing.T) {
	a, _ := localOAuth(t)
	code := login(t, a.oauth, authorizeValues())
	if w := exchange(a.oauth, code, strings.Repeat("x", 43), testResource); w.Code != 400 {
		t.Fatal("wrong verifier accepted")
	}
	if w := exchange(a.oauth, code, testVerifier, testResource); w.Code != 400 {
		t.Fatal("failed code was not burned")
	}
	code = login(t, a.oauth, authorizeValues())
	if w := exchange(a.oauth, code, testVerifier, "https://other.example"); w.Code != 400 {
		t.Fatal("wrong resource accepted")
	}
}

func TestCodeConsumptionIsAtomic(t *testing.T) {
	a, _ := localOAuth(t)
	code := login(t, a.oauth, authorizeValues())
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- exchange(a.oauth, code, testVerifier, testResource).Code }()
	}
	wg.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful exchanges: %d", success)
	}
}

func TestDiscoveryAndScopeChallenge(t *testing.T) {
	a, store := localOAuth(t)
	w := httptest.NewRecorder()
	a.HandleAuthorizationServerMetadata(w, httptest.NewRequest("GET", testResource+"/.well-known/oauth-authorization-server", nil))
	if !strings.Contains(w.Body.String(), `"code_challenge_methods_supported":["S256"]`) || !strings.Contains(w.Body.String(), `"authorization_response_iss_parameter_supported":true`) {
		t.Fatal(w.Body.String())
	}
	token, err := store.issueToken(time.Hour, "tools.read", testResource, testResource)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", testResource+"/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token.Value)
	w = httptest.NewRecorder()
	a.WriteUnauthorized(w, r, "tools.execute")
	if w.Code != 403 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("bad scope challenge: %d %s", w.Code, w.Header())
	}
	if a.SecuritySchemes()[0]["type"] != "oauth2" {
		t.Fatal("OAuth tool metadata missing")
	}
}
