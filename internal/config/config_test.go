package config

import "testing"

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
