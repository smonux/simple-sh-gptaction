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
	OAuthTokenTTLSeconds int
	OAuthCodeTTLSeconds  int
	OAuthAllowedScopes   []string
	OAuthRedirectURIs    []string
	OAuthUsername        string
	OAuthPassword        string
	OAuthSQLitePath      string
	PublicURL            string
	AuthServerURL        string
	Logf                 func(string, ...any)
}

type Authorizer struct {
	mode          Mode
	apiKey        string
	oauth         *OAuthServer
	publicURL     string
	authServerURL string
	logf          func(string, ...any)
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
		if cfg.OAuthClientID == "" {
			return nil, fmt.Errorf("OAUTH_CLIENT_ID is required for auth mode %q", mode)
		}
	case ModeAny:
		if cfg.APIKey == "" && cfg.OAuthClientID == "" {
			return nil, fmt.Errorf("API_KEY or OAUTH_CLIENT_ID are required for auth mode %q", mode)
		}
	default:
		return nil, fmt.Errorf("invalid AUTH_MODE %q", cfg.Mode)
	}

	var (
		oauth *OAuthServer
		err   error
	)
	if cfg.OAuthClientID != "" {
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
			TokenTTL:      ttl,
			CodeTTL:       codeTTL,
			AllowedScopes: cfg.OAuthAllowedScopes,
			RedirectURIs:  cfg.OAuthRedirectURIs,
			Username:      cfg.OAuthUsername,
			Password:      cfg.OAuthPassword,
			Logf:          cfg.Logf,
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
		logf:          cfg.Logf,
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
		a.logAuth("missing bearer token", r)
		return false
	}
	switch a.mode {
	case ModeAPIKey:
		ok := subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1
		if !ok {
			a.logAuth("api key mismatch", r)
		}
		return ok
	case ModeOAuth:
		if a.oauth == nil {
			a.logAuth("oauth not configured", r)
			return false
		}
		ok := a.oauth.Validate(token)
		if !ok {
			a.logAuth("oauth token invalid", r)
		}
		return ok
	case ModeAny:
		if a.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
			return true
		}
		if a.oauth == nil {
			a.logAuth("oauth not configured", r)
			return false
		}
		ok := a.oauth.Validate(token)
		if !ok {
			a.logAuth("oauth token invalid", r)
		}
		return ok
	default:
		return false
	}
}

func (a *Authorizer) WriteUnauthorized(w http.ResponseWriter, r *http.Request) {
	a.logAuth("unauthorized", r)
	if a.mode == ModeOAuth || a.mode == ModeAny {
		metaURL := a.resourceMetadataURL(r)
		if metaURL != "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", metaURL))
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func (a *Authorizer) logAuth(msg string, r *http.Request) {
	if a.logf == nil {
		return
	}
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	remote := ""
	if r != nil {
		remote = r.RemoteAddr
	}
	a.logf("auth: %s method=%s path=%s remote=%s", msg, safeMethod(r), path, remote)
}

func safeMethod(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Method
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
