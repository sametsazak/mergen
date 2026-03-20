package checks

// CIS 2.3.3.2 — File sharing disabled

func init() {
	Register(newCheck(
		"2.3.3.2", "File sharing disabled",
		"2", "CIS Benchmark", "High",
		"SMB/AFP file sharing exposes the filesystem to the network.",
		"sudo launchctl disable system/com.apple.smbd",
		false,
		adminFix(
			"launchctl disable system/com.apple.smbd; launchctl stop com.apple.smbd 2>/dev/null; true",
			"File Sharing (SMB/AFP) service will be disabled and stopped.",
		),
		func() Result {
			if !launchctlDisabled("com.apple.smbd") {
				return Result{StatusFail, "File sharing (smbd) is not disabled"}
			}
			return Result{StatusPass, "File sharing is disabled"}
		},
	))
}
