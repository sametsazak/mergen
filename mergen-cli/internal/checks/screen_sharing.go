package checks

// CIS 2.3.3.1 — Screen sharing disabled

func init() {
	Register(newCheck(
		"2.3.3.1", "Screen sharing disabled",
		"2", "CIS Benchmark", "High",
		"Screen sharing allows remote visual access to this Mac. Disable unless explicitly required.",
		"sudo launchctl disable system/com.apple.screensharing",
		false,
		adminFix(
			"launchctl disable system/com.apple.screensharing; launchctl stop com.apple.screensharing 2>/dev/null; true",
			"Screen Sharing service will be disabled and stopped.",
		),
		func() Result {
			if launchctlRunning("com.apple.screensharing") {
				return Result{StatusFail, "Screen sharing is running"}
			}
			return Result{StatusPass, "Screen sharing is not running"}
		},
	))
}
