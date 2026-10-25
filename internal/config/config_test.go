package config

import "testing"

func TestRefreshGrantLifetime(t *testing.T) {
	t.Setenv("AUTH_MODE", "none")
	for _, tc := range []struct {
		value   string
		want    int
		invalid bool
	}{
		{"", DefaultRefreshTTL, false}, {"86400", 86400, false},
		{"0", 0, true}, {"-1", -1, true}, {"31536001", 31536001, true},
	} {
		t.Setenv("OAUTH_REFRESH_TOKEN_TTL_SECONDS", tc.value)
		cfg, err := LoadServerConfig()
		if (err != nil) != tc.invalid || cfg.OAuthRefreshTTLSeconds != tc.want {
			t.Fatalf("refresh TTL %q: value=%d err=%v", tc.value, cfg.OAuthRefreshTTLSeconds, err)
		}
	}
}

func TestDisableAction(t *testing.T) {
	t.Setenv("AUTH_MODE", "none")
	for _, tc := range []struct {
		value             string
		disabled, invalid bool
	}{
		{"", false, false}, {"false", false, false}, {"true", true, false}, {"typo", false, true},
	} {
		t.Setenv("DISABLE_ACTION", tc.value)
		cfg, err := LoadServerConfig()
		if (err != nil) != tc.invalid || cfg.DisableAction != tc.disabled {
			t.Fatalf("DISABLE_ACTION=%q: %+v, %v", tc.value, cfg, err)
		}
	}
}
