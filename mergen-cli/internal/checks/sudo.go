package checks

// CIS 5.4  — Sudo timeout = 0
// CIS 5.5  — Sudo TTY tickets
// CIS 5.11 — Sudo logging

func init() {
	Register(newCheck(
		"5.4", "Sudo timeout configured",
		"5", "CIS Benchmark", "Medium",
		"Sudo should require password re-entry for every command (timestamp_timeout=0).",
		"echo 'Defaults timestamp_timeout=0' | sudo tee /etc/sudoers.d/cis_timeout && sudo chmod 440 /etc/sudoers.d/cis_timeout",
		false,
		adminFix(
			"echo 'Defaults timestamp_timeout=0' | tee /etc/sudoers.d/cis_timeout && chmod 440 /etc/sudoers.d/cis_timeout",
			"sudo will require your password every time — no grace period between commands.",
		),
		func() Result {
			out, err := shell("sudo -V 2>&1 | grep 'Authentication timestamp timeout'")
			if err != nil {
				return Result{StatusWarn, "Could not read sudo configuration"}
			}
			if contains(out, "0.0 minutes") {
				return Result{StatusPass, "sudo timeout = 0 (re-auth required every time)"}
			}
			return Result{StatusFail, "sudo timeout is not 0: " + out}
		},
	))

	Register(newCheck(
		"5.5", "Sudo TTY tickets enabled",
		"5", "CIS Benchmark", "Medium",
		"TTY tickets scope sudo auth per terminal so one window can't elevate another.",
		"echo 'Defaults timestamp_type=tty' | sudo tee /etc/sudoers.d/cis_tty && sudo chmod 440 /etc/sudoers.d/cis_tty",
		false,
		adminFix(
			"echo 'Defaults timestamp_type=tty' | tee /etc/sudoers.d/cis_tty && chmod 440 /etc/sudoers.d/cis_tty",
			"sudo authentication will be scoped per terminal window (TTY tickets).",
		),
		func() Result {
			out, err := shell("grep -r 'timestamp_type' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
			if err == nil && contains(out, "tty") {
				return Result{StatusPass, "sudo TTY tickets are enabled"}
			}
			return Result{StatusFail, "sudo TTY tickets are not configured"}
		},
	))

	Register(newCheck(
		"5.11", "Sudo logging enabled",
		"5", "CIS Benchmark", "Medium",
		"Logging sudo commands creates an audit trail of all privileged actions.",
		"echo 'Defaults log_allowed' | sudo tee /etc/sudoers.d/cis_logging && sudo chmod 440 /etc/sudoers.d/cis_logging",
		false,
		adminFix(
			"echo 'Defaults log_allowed' | tee /etc/sudoers.d/cis_logging && chmod 440 /etc/sudoers.d/cis_logging",
			"sudo will log all allowed commands to the system log.",
		),
		func() Result {
			out, err := shell("grep -r 'log_allowed' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
			if err == nil && contains(out, "log_allowed") {
				return Result{StatusPass, "sudo command logging is enabled"}
			}
			return Result{StatusFail, "sudo command logging is not configured"}
		},
	))
}
