package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultListenAddr   = "127.0.0.1:9000"
	DefaultMaxOutput    = 200000
	DefaultTimeoutMs    = 45000
	DefaultBashPath     = "/bin/bash"
	DefaultAllowIOCTL   = false
	DefaultExecutorPath = "./executor"
	DefaultAuthMode     = "api_key"
	DefaultTokenTTL     = 3600
	DefaultCodeTTL      = 600
)

type ServerConfig struct {
	ListenAddr           string
	APIKey               string
	MaxOutputChar        int
	ExecutorPath         string
	AuthMode             string
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
}

type ExecutorConfig struct {
	WriteAllow       []string
	BindTCPAllow     []uint16
	AllowOutgoingTCP bool
	BashPath         string
	AllowIOCTLDev    bool
}

func LoadServerConfig() (ServerConfig, error) {
	cfg := ServerConfig{
		ListenAddr:           envOr("LISTEN_ADDR", DefaultListenAddr),
		APIKey:               os.Getenv("API_KEY"),
		MaxOutputChar:        envInt("MAX_OUTPUT_CHARS", DefaultMaxOutput),
		ExecutorPath:         envOr("EXECUTOR_PATH", DefaultExecutorPath),
		AuthMode:             envOr("AUTH_MODE", DefaultAuthMode),
		OAuthClientID:        strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		OAuthTokenTTLSeconds: envInt("OAUTH_TOKEN_TTL_SECONDS", DefaultTokenTTL),
		OAuthCodeTTLSeconds:  envInt("OAUTH_CODE_TTL_SECONDS", DefaultCodeTTL),
		OAuthAllowedScopes:   splitSpaceList(os.Getenv("OAUTH_ALLOWED_SCOPES")),
		OAuthRedirectURIs:    splitSpaceList(os.Getenv("OAUTH_REDIRECT_URIS")),
		OAuthUsername:        strings.TrimSpace(os.Getenv("OAUTH_USERNAME")),
		OAuthPassword:        strings.TrimSpace(os.Getenv("OAUTH_PASSWORD")),
		OAuthSQLitePath:      strings.TrimSpace(os.Getenv("OAUTH_SQLITE_PATH")),
		PublicURL:            strings.TrimRight(strings.TrimSpace(os.Getenv("PUBLIC_URL")), "/"),
		AuthServerURL:        strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_SERVER_URL")), "/"),
	}
	authMode := strings.ToLower(strings.TrimSpace(cfg.AuthMode))
	switch authMode {
	case "api_key":
		if cfg.APIKey == "" {
			return cfg, fmt.Errorf("API_KEY is required for AUTH_MODE=api_key")
		}
	case "oauth":
		if cfg.OAuthClientID == "" {
			return cfg, fmt.Errorf("OAUTH_CLIENT_ID is required for AUTH_MODE=oauth")
		}
		if cfg.OAuthSQLitePath == "" {
			return cfg, fmt.Errorf("OAUTH_SQLITE_PATH is required for AUTH_MODE=oauth")
		}
		if cfg.OAuthUsername == "" || cfg.OAuthPassword == "" {
			return cfg, fmt.Errorf("OAUTH_USERNAME and OAUTH_PASSWORD are required for AUTH_MODE=oauth")
		}
	case "any":
		if cfg.APIKey == "" && cfg.OAuthClientID == "" {
			return cfg, fmt.Errorf("API_KEY or OAUTH_CLIENT_ID are required for AUTH_MODE=any")
		}
		if cfg.OAuthClientID != "" {
			if cfg.OAuthSQLitePath == "" {
				return cfg, fmt.Errorf("OAUTH_SQLITE_PATH is required when OAuth is enabled")
			}
			if cfg.OAuthUsername == "" || cfg.OAuthPassword == "" {
				return cfg, fmt.Errorf("OAUTH_USERNAME and OAUTH_PASSWORD are required when OAuth is enabled")
			}
		}
	case "none":
	default:
		return cfg, fmt.Errorf("invalid AUTH_MODE %q", cfg.AuthMode)
	}
	return cfg, nil
}

func LoadExecutorConfig() (ExecutorConfig, error) {
	writeAllow := splitList(os.Getenv("WRITE_ALLOW"))
	bindAllow, err := parsePorts(os.Getenv("BIND_TCP_ALLOW"))
	if err != nil {
		return ExecutorConfig{}, err
	}
	allowOutgoing, err := envBool("ALLOW_OUTGOING_TCP", false)
	if err != nil {
		return ExecutorConfig{}, err
	}
	allowIOCTL, err := envBool("ALLOW_IOCTL_DEV", DefaultAllowIOCTL)
	if err != nil {
		return ExecutorConfig{}, err
	}
	cfg := ExecutorConfig{
		WriteAllow:       writeAllow,
		BindTCPAllow:     bindAllow,
		AllowOutgoingTCP: allowOutgoing,
		BashPath:         envOr("BASH_PATH", DefaultBashPath),
		AllowIOCTLDev:    allowIOCTL,
	}
	return cfg, nil
}

func envOr(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("invalid %s: %w", key, err)
	}
	return b, nil
}

func envBoolLoose(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitSpaceList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.Fields(v)
}

func parsePorts(v string) ([]uint16, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	parts := strings.Split(v, ":")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port64, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if port64 == 0 {
			return nil, fmt.Errorf("bind port 0 is not allowed")
		}
		out = append(out, uint16(port64))
	}
	return out, nil
}
