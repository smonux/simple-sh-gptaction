package config

import (
	"slices"
	"strings"
	"testing"
)

func TestChildEnvironmentDoesNotInheritCredentialsOrStartupHooks(t *testing.T) {
	input := []string{
		"PATH=/usr/bin:/bin", "HOME=/home/test", "LANG=C.UTF-8", "LC_TIME=C",
		"WRITE_ALLOW=/tmp", "BASH_PATH=/bin/bash", "ALLOW_OUTGOING_TCP=false",
		"API_KEY=secret", "OAUTH_PASSWORD=secret", "AWS_SECRET_ACCESS_KEY=secret",
		"CUSTOM_SECRET=secret", "LD_PRELOAD=/tmp/attack.so", "BASH_ENV=/tmp/attack.sh", "ENV=/tmp/attack.sh",
		"LC_SECRET=secret",
	}
	for _, env := range [][]string{ExecutorEnvironment(input), ShellEnvironment(input)} {
		for _, secret := range input[7:] {
			if slices.Contains(env, secret) {
				name, _, _ := strings.Cut(secret, "=")
				t.Fatalf("unsafe child environment variable: %s", name)
			}
		}
		if !slices.Contains(env, "PATH=/usr/bin:/bin") || !slices.Contains(env, "HOME=/home/test") {
			t.Fatal("user shell settings were lost")
		}
	}
	if !slices.Contains(ExecutorEnvironment(input), "WRITE_ALLOW=/tmp") {
		t.Fatal("executor lost policy")
	}
	if slices.Contains(ShellEnvironment(input), "WRITE_ALLOW=/tmp") {
		t.Fatal("internal policy leaked into shell environment")
	}
}
