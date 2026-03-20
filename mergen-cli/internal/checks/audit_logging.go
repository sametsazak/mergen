package checks

import "strings"

// CIS 3.1 — Security auditing enabled
// CIS 3.2 — Audit flags configured

func init() {
	Register(newCheck(
		"3.1", "Security auditing enabled",
		"3", "CIS Benchmark", "Medium",
		"The macOS audit daemon (auditd) records security-relevant events for forensic analysis.",
		"sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist",
		false, nil,
		func() Result {
			out, err := run("/bin/launchctl", "list", "com.apple.auditd")
			if err != nil || strings.Contains(out, "Could not find") {
				return Result{StatusWarn, "auditd is not running (may be removed in macOS Tahoe)"}
			}
			return Result{StatusPass, "auditd is running"}
		},
	))

	Register(newCheck(
		"3.2", "Audit flags configured",
		"3", "CIS Benchmark", "Medium",
		"Audit flags should capture login/logout (lo), auth (aa), admin (ad), file deletion (fd, fm).",
		"Edit /etc/security/audit_control and set: flags=lo,aa,ad,fd,fm,-all",
		false, nil,
		func() Result {
			out, err := shell("grep ^flags /etc/security/audit_control 2>/dev/null")
			if err != nil || out == "" {
				return Result{StatusWarn, "audit_control not found or flags line missing"}
			}
			required := []string{"lo", "aa", "ad", "fd", "fm"}
			var missing []string
			for _, flag := range required {
				if !strings.Contains(out, flag) {
					missing = append(missing, flag)
				}
			}
			if len(missing) > 0 {
				return Result{StatusFail, "Missing audit flags: " + strings.Join(missing, ", ") + " (current: " + out + ")"}
			}
			return Result{StatusPass, "Audit flags configured: " + out}
		},
	))
}
