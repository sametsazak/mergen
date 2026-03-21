package checks

// Fast User Switching disabled

func init() {
	Register(newCheck(
		"", "Fast user switching disabled",
		"2", "CIS Benchmark", "Medium",
		"Fast User Switching lets users switch accounts without logging out, which can leave sessions exposed.",
		"sudo defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false",
		false,
		adminFix(
			"defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false",
			"Fast User Switching will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/.GlobalPreferences", "MultipleSessionEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Fast User Switching is enabled"}
			}
			return Result{StatusPass, "Fast User Switching is disabled"}
		},
	))
}
