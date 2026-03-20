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
				return Result{StatusPass, "Root account is disabled or has no shell configured"}
			}
			if contains(out, "/usr/bin/false") || contains(out, "nologin") {
				return Result{StatusPass, "Root account is disabled (shell: /usr/bin/false)"}
			}
			if contains(out, "/bin/sh") || contains(out, "/bin/zsh") || contains(out, "/bin/bash") {
				return Result{StatusFail, "Root account has an active shell: " + trim(out)}
			}
			return Result{StatusWarn, "Root account shell status unclear: " + trim(out)}
		},
	))
}
