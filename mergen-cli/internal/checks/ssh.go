package checks

// CIS 2.3.3.4 — Remote Login (SSH) disabled

func init() {
	Register(newCheck(
		"2.3.3.4", "Remote login (SSH) disabled",
		"2", "CIS Benchmark", "High",
		"SSH provides remote shell access and should be disabled unless explicitly required.",
		"sudo launchctl disable system/com.openssh.sshd",
		false,
		adminFix(
			"launchctl disable system/com.openssh.sshd; launchctl stop com.openssh.sshd 2>/dev/null; true",
			"Remote Login (SSH) service will be disabled and stopped.",
		),
		func() Result {
			if !launchctlDisabled("com.openssh.sshd") {
				return Result{StatusFail, "SSH (Remote Login) is not disabled"}
			}
			return Result{StatusPass, "SSH is disabled"}
		},
	))
}
