package config

import "strings"

// Only these user/session settings belong in the personal shell. In particular,
// do not forward OAuth, API keys, cloud credentials, or loader/startup hooks.
func shellVariable(name string) bool {
	switch name {
	case "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TERM", "TZ", "TMPDIR",
		"LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_NUMERIC", "LC_TIME",
		"LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION":
		return true
	}
	return false
}

func executorVariable(name string) bool {
	switch name {
	case "WRITE_ALLOW", "BIND_TCP_ALLOW", "ALLOW_OUTGOING_TCP", "BASH_PATH", "ALLOW_IOCTL_DEV":
		return true
	}
	return false
}

func filterEnvironment(environ []string, includeExecutor bool) []string {
	clean := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, valid := strings.Cut(entry, "=")
		if valid && (shellVariable(name) || (includeExecutor && executorVariable(name))) {
			clean = append(clean, entry)
		}
	}
	return clean
}

func ExecutorEnvironment(environ []string) []string {
	return filterEnvironment(environ, true)
}

func ShellEnvironment(environ []string) []string {
	return filterEnvironment(environ, false)
}
