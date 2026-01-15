package auth

import (
	"encoding/json"
	"net/http"
)

func (a *Authorizer) HandleProtectedResource(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	base := a.resourceBaseURL(r)
	issuer := a.issuerURL(r)
	if base == "" || issuer == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"resource":              base,
		"authorization_servers": []string{issuer},
	}
	if scopes := a.oauthAllowedScopes(); len(scopes) > 0 {
		resp["scopes_supported"] = scopes
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Authorizer) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	issuer := a.issuerURL(r)
	if issuer == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	if scopes := a.oauthAllowedScopes(); len(scopes) > 0 {
		resp["scopes_supported"] = scopes
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Authorizer) oauthAllowedScopes() []string {
	if a.oauth == nil || len(a.oauth.allowedScopes) == 0 {
		return nil
	}
	out := make([]string, 0, len(a.oauth.allowedScopes))
	for s := range a.oauth.allowedScopes {
		out = append(out, s)
	}
	return out
}
