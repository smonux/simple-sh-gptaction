package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthConfig struct {
	ClientID      string
	ClientSecret  string
	TokenTTL      time.Duration
	CodeTTL       time.Duration
	AllowedScopes []string
	RedirectURIs  []string
	Username      string
	Password      string
	AutoApprove   bool
	TokenStore    tokenStore
	CodeStore     codeStore
}

type OAuthServer struct {
	clientID      string
	clientSecret  string
	tokenTTL      time.Duration
	codeTTL       time.Duration
	allowedScopes map[string]struct{}
	redirectURIs  map[string]struct{}
	username      string
	password      string
	autoApprove   bool
	tokens        tokenStore
	codes         codeStore
}

func NewOAuthServer(cfg OAuthConfig) (*OAuthServer, error) {
	allowed := map[string]struct{}{}
	for _, scope := range cfg.AllowedScopes {
		if scope == "" {
			continue
		}
		allowed[scope] = struct{}{}
	}
	redirects := map[string]struct{}{}
	for _, uri := range cfg.RedirectURIs {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		redirects[uri] = struct{}{}
	}
	if cfg.TokenStore == nil || cfg.CodeStore == nil {
		return nil, fmt.Errorf("oauth token/code stores are required")
	}
	return &OAuthServer{
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		tokenTTL:      cfg.TokenTTL,
		codeTTL:       cfg.CodeTTL,
		allowedScopes: allowed,
		redirectURIs:  redirects,
		username:      cfg.Username,
		password:      cfg.Password,
		autoApprove:   cfg.AutoApprove,
		tokens:        cfg.TokenStore,
		codes:         cfg.CodeStore,
	}, nil
}

func (o *OAuthServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	params, err := parseAuthorizeParams(r)
	if err != nil {
		o.writeAuthorizeError(w, r, params, "invalid_request", err.Error())
		return
	}
	if !subtleCompare(params.ClientID, o.clientID) {
		o.writeAuthorizeError(w, r, params, "unauthorized_client", "unknown client_id")
		return
	}
	if params.ResponseType != "code" {
		o.writeAuthorizeError(w, r, params, "unsupported_response_type", "response_type must be code")
		return
	}
	redirectURI, err := o.resolveRedirectURI(params.RedirectURI)
	if err != nil {
		o.writeAuthorizeError(w, r, params, "invalid_request", err.Error())
		return
	}
	params.RedirectURI = redirectURI

	if params.CodeChallenge == "" {
		o.writeAuthorizeError(w, r, params, "invalid_request", "code_challenge is required")
		return
	}
	method := params.CodeChallengeMethod
	if method == "" {
		method = "plain"
	}
	if method != "S256" && method != "plain" {
		o.writeAuthorizeError(w, r, params, "invalid_request", "unsupported code_challenge_method")
		return
	}
	params.CodeChallengeMethod = method

	if !o.autoApprove {
		if o.username == "" || o.password == "" {
			http.Error(w, "authorization server not configured for interactive login", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodGet {
			o.renderLogin(w, params, "")
			return
		}
		if err := r.ParseForm(); err != nil {
			o.renderLogin(w, params, "invalid form")
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		pass := strings.TrimSpace(r.FormValue("password"))
		if !subtleCompare(user, o.username) || !subtleCompare(pass, o.password) {
			o.renderLogin(w, params, "invalid credentials")
			return
		}
	}

	scope := o.filterScopes(params.Scope)
	code, err := o.codes.issueCode(o.codeTTL, codeInfo{
		clientID:            o.clientID,
		redirectURI:         params.RedirectURI,
		codeChallenge:       params.CodeChallenge,
		codeChallengeMethod: params.CodeChallengeMethod,
		scope:               scope,
	})
	if err != nil {
		http.Error(w, "failed to issue code", http.StatusInternalServerError)
		return
	}

	redirect, err := buildRedirectURL(params.RedirectURI, code, params.State, "")
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (o *OAuthServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret := parseClientCredentials(r)
	if !o.validClient(clientID, clientSecret) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	grantType := strings.TrimSpace(r.FormValue("grant_type"))
	if grantType == "" {
		grantType = "authorization_code"
	}
	if grantType != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	verifier := strings.TrimSpace(r.FormValue("code_verifier"))
	if code == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}
	if redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	scope, err := o.codes.consumeCode(code, clientID, redirectURI, verifier)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	token, err := o.tokens.issueToken(o.tokenTTL, scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}
	resp := map[string]any{
		"access_token": token.Value,
		"token_type":   "Bearer",
		"expires_in":   int(token.TTL.Seconds()),
	}
	if scope != "" {
		resp["scope"] = scope
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (o *OAuthServer) Validate(token string) bool {
	ok, _ := o.tokens.validateToken(token)
	return ok
}

func (o *OAuthServer) filterScopes(scope string) string {
	if scope == "" || len(o.allowedScopes) == 0 {
		return scope
	}
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if _, ok := o.allowedScopes[s]; ok {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

func (o *OAuthServer) validClient(id, secret string) bool {
	if id == "" || secret == "" {
		return false
	}
	return subtleCompare(id, o.clientID) && subtleCompare(secret, o.clientSecret)
}

func (o *OAuthServer) resolveRedirectURI(redirectURI string) (string, error) {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		if len(o.redirectURIs) == 1 {
			for uri := range o.redirectURIs {
				return uri, nil
			}
		}
		return "", fmt.Errorf("redirect_uri is required")
	}
	if len(o.redirectURIs) == 0 {
		return redirectURI, nil
	}
	if _, ok := o.redirectURIs[redirectURI]; !ok {
		return "", fmt.Errorf("redirect_uri not allowed")
	}
	return redirectURI, nil
}

func (o *OAuthServer) renderLogin(w http.ResponseWriter, params authorizeParams, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorize</title></head><body>")
	b.WriteString("<h1>Authorize</h1>")
	if errMsg != "" {
		b.WriteString("<p style=\"color:red\">")
		b.WriteString(html.EscapeString(errMsg))
		b.WriteString("</p>")
	}
	b.WriteString("<form method=\"post\">")
	b.WriteString("<label>Username <input name=\"username\" /></label><br/>")
	b.WriteString("<label>Password <input type=\"password\" name=\"password\" /></label><br/>")
	writeHidden(&b, "response_type", params.ResponseType)
	writeHidden(&b, "client_id", params.ClientID)
	writeHidden(&b, "redirect_uri", params.RedirectURI)
	writeHidden(&b, "scope", params.Scope)
	writeHidden(&b, "state", params.State)
	writeHidden(&b, "code_challenge", params.CodeChallenge)
	writeHidden(&b, "code_challenge_method", params.CodeChallengeMethod)
	b.WriteString("<button type=\"submit\">Authorize</button>")
	b.WriteString("</form></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

func writeHidden(b *strings.Builder, name, value string) {
	if value == "" {
		return
	}
	b.WriteString("<input type=\"hidden\" name=\"")
	b.WriteString(html.EscapeString(name))
	b.WriteString("\" value=\"")
	b.WriteString(html.EscapeString(value))
	b.WriteString("\"/>")
}

func parseAuthorizeParams(r *http.Request) (authorizeParams, error) {
	var params authorizeParams
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return params, err
		}
		values = r.Form
	}
	params.ResponseType = strings.TrimSpace(values.Get("response_type"))
	params.ClientID = strings.TrimSpace(values.Get("client_id"))
	params.RedirectURI = strings.TrimSpace(values.Get("redirect_uri"))
	params.Scope = strings.TrimSpace(values.Get("scope"))
	params.State = strings.TrimSpace(values.Get("state"))
	params.CodeChallenge = strings.TrimSpace(values.Get("code_challenge"))
	params.CodeChallengeMethod = strings.TrimSpace(values.Get("code_challenge_method"))
	if params.ClientID == "" {
		return params, fmt.Errorf("client_id is required")
	}
	if params.ResponseType == "" {
		params.ResponseType = "code"
	}
	return params, nil
}

func (o *OAuthServer) writeAuthorizeError(w http.ResponseWriter, r *http.Request, params authorizeParams, code, desc string) {
	if params.RedirectURI == "" {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	redirectURI, err := o.resolveRedirectURI(params.RedirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	redirect, err := buildRedirectURL(redirectURI, "", params.State, code)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func buildRedirectURL(redirectURI, code, state, errCode string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	if errCode != "" {
		q.Set("error", errCode)
	} else {
		q.Set("code", code)
	}
	if state != "" {
		q.Set("state", state)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func parseClientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := parseBasicAuth(r.Header.Get("Authorization")); ok {
		return id, secret
	}
	return strings.TrimSpace(r.FormValue("client_id")), strings.TrimSpace(r.FormValue("client_secret"))
}

func parseBasicAuth(header string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

type authorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type tokenStore interface {
	issueToken(ttl time.Duration, scope string) (issuedToken, error)
	validateToken(token string) (bool, error)
}

type issuedToken struct {
	Value string
	TTL   time.Duration
}

type codeInfo struct {
	clientID            string
	redirectURI         string
	codeChallenge       string
	codeChallengeMethod string
	scope               string
	expiresAt           time.Time
}

type codeStore interface {
	issueCode(ttl time.Duration, info codeInfo) (string, error)
	consumeCode(code, clientID, redirectURI, verifier string) (string, error)
}

func verifyPKCE(method, challenge, verifier string) bool {
	if method == "" {
		method = "plain"
	}
	switch method {
	case "plain":
		return subtleCompare(challenge, verifier)
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtleCompare(challenge, encoded)
	default:
		return false
	}
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(errors.New("failed to generate token"))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := 0; i < len(a); i++ {
		out |= a[i] ^ b[i]
	}
	return out == 0
}
