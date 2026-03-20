package checks

// CIS 5.6 — Root account disabled

func init() {
	Register(newCheck(
		"5.6", "Root account disabled",
		"5", "CIS Benchmark", "High",
		"The root account should be disabled to prevent direct root login.",
		"sudo dsenableroot -d",
		false,
		adminFix(
			"dsenableroot -d",
			"Root account will be disabled.",
		),
		func() Result {
			out, err := run("/usr/bin/dscl", ".", "-read", "/Users/root", "UserShell")
			if err != nil {
				return Result{StatusPass, "Root account is disabled or inaccessible"}
			}
			if contains(out, "/usr/bin/false") || contains(out, "nologin") {
				return Result{StatusPass, "Root account is disabled"}
			}
			return Result{StatusFail, "Root account is enabled: " + out}
		},
	))
}
