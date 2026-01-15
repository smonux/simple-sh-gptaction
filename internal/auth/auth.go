package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Mode string

const (
	ModeNone   Mode = "none"
	ModeAPIKey Mode = "api_key"
	ModeOAuth  Mode = "oauth"
	ModeAny    Mode = "any"
)

type Config struct {
	Mode                 string
	APIKey               string
	OAuthClientID        string
	OAuthClientSecret    string
	OAuthTokenTTLSeconds int
	OAuthCodeTTLSeconds  int
	OAuthAllowedScopes   []string
	OAuthRedirectURIs    []string
	OAuthUsername        string
	OAuthPassword        string
	OAuthAutoApprove     bool
	OAuthSQLitePath      string
	PublicURL            string
	AuthServerURL        string
}

type Authorizer struct {
	mode          Mode
	apiKey        string
	oauth         *OAuthServer
	publicURL     string
	authServerURL string
}

func NewAuthorizer(cfg Config) (*Authorizer, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(cfg.Mode)))
	if mode == "" {
		mode = ModeAPIKey
	}

	switch mode {
	case ModeNone:
	case ModeAPIKey:
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("API_KEY is required for auth mode %q", mode)
		}
	case ModeOAuth:
		if cfg.OAuthClientID == "" || cfg.OAuthClientSecret == "" {
			return nil, fmt.Errorf("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET are required for auth mode %q", mode)
		}
	case ModeAny:
		if cfg.APIKey == "" && (cfg.OAuthClientID == "" || cfg.OAuthClientSecret == "") {
			return nil, fmt.Errorf("API_KEY or OAuth client credentials are required for auth mode %q", mode)
		}
	default:
		return nil, fmt.Errorf("invalid AUTH_MODE %q", cfg.Mode)
	}

	var (
		oauth *OAuthServer
		err   error
	)
	if cfg.OAuthClientID != "" && cfg.OAuthClientSecret != "" {
		var tokenStore tokenStore
		var codeStore codeStore
		if cfg.OAuthSQLitePath != "" {
			sqlStore, err := newSQLiteStore(cfg.OAuthSQLitePath)
			if err != nil {
				return nil, err
			}
			tokenStore = sqlStore
			codeStore = sqlStore
		}
		ttl := time.Duration(cfg.OAuthTokenTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = time.Hour
		}
		codeTTL := time.Duration(cfg.OAuthCodeTTLSeconds) * time.Second
		if codeTTL <= 0 {
			codeTTL = 5 * time.Minute
		}
		oauth, err = NewOAuthServer(OAuthConfig{
			ClientID:      cfg.OAuthClientID,
			ClientSecret:  cfg.OAuthClientSecret,
			TokenTTL:      ttl,
			CodeTTL:       codeTTL,
			AllowedScopes: cfg.OAuthAllowedScopes,
			RedirectURIs:  cfg.OAuthRedirectURIs,
			Username:      cfg.OAuthUsername,
			Password:      cfg.OAuthPassword,
			AutoApprove:   cfg.OAuthAutoApprove,
			TokenStore:    tokenStore,
			CodeStore:     codeStore,
		})
		if err != nil {
			return nil, err
		}
	}

	return &Authorizer{
		mode:          mode,
		apiKey:        cfg.APIKey,
		oauth:         oauth,
		publicURL:     strings.TrimRight(cfg.PublicURL, "/"),
		authServerURL: strings.TrimRight(cfg.AuthServerURL, "/"),
	}, nil
}

func (a *Authorizer) OAuth() *OAuthServer {
	return a.oauth
}

func (a *Authorizer) AuthorizeRequest(r *http.Request) bool {
	if a.mode == ModeNone {
		return true
	}
	token := parseBearer(r)
	if token == "" {
		return false
	}
	switch a.mode {
	case ModeAPIKey:
		return subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1
	case ModeOAuth:
		return a.oauth != nil && a.oauth.Validate(token)
	case ModeAny:
		if a.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
			return true
		}
		return a.oauth != nil && a.oauth.Validate(token)
	default:
		return false
	}
}

func (a *Authorizer) WriteUnauthorized(w http.ResponseWriter, r *http.Request) {
	if a.mode == ModeOAuth || a.mode == ModeAny {
		metaURL := a.resourceMetadataURL(r)
		if metaURL != "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", metaURL))
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func (a *Authorizer) resourceMetadataURL(r *http.Request) string {
	base := a.resourceBaseURL(r)
	if base == "" {
		return ""
	}
	return base + "/.well-known/oauth-protected-resource"
}

func (a *Authorizer) resourceBaseURL(r *http.Request) string {
	if a.publicURL != "" {
		return a.publicURL
	}
	return requestBaseURL(r)
}

func (a *Authorizer) issuerURL(r *http.Request) string {
	if a.authServerURL != "" {
		return a.authServerURL
	}
	if a.publicURL != "" {
		return a.publicURL
	}
	return requestBaseURL(r)
}

func parseBearer(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
}

func requestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if xfHost := r.Header.Get("X-Forwarded-Host"); xfHost != "" {
		host = xfHost
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}
