package checks

import (
	"os/exec"
	"strings"
)

// shell runs a shell command and returns combined stdout+stderr, trimmed.
func shell(command string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// run executes a binary with args and returns combined output, trimmed.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// defaultsRead reads a single defaults key. Returns ("", error) if key absent.
func defaultsRead(domain, key string) (string, error) {
	return run("/usr/bin/defaults", "read", domain, key)
}

// defaultsReadHost reads a -currentHost defaults key.
func defaultsReadHost(domain, key string) (string, error) {
	return run("/usr/bin/defaults", "-currentHost", "read", domain, key)
}

// launchctlDisabled returns true when the given service label is listed as
// disabled in `launchctl print-disabled system`.
func launchctlDisabled(label string) bool {
	out, err := run("/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return false
	}
	needle := `"` + label + `" => disabled`
	return strings.Contains(out, needle)
}

// launchctlRunning returns true when the service is currently loaded/running.
func launchctlRunning(label string) bool {
	_, err := run("/bin/launchctl", "list", label)
	return err == nil
}

// contains is a case-insensitive substring check.
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// trim strips whitespace and newlines.
func trim(s string) string {
	return strings.TrimSpace(s)
}

// unknownWarn returns a StatusWarn result when a check can't determine status
// due to a command error — matches the Swift app's Yellow-on-exception behaviour.
func unknownWarn(context string) Result {
	return Result{StatusWarn, "Could not determine: " + context}
}

// join joins a slice of strings with a separator.
func join(parts []string, sep string) string {
	return strings.Join(parts, sep)
}
