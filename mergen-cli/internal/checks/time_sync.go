package checks

// CIS 2.3.2.1 — Time set automatically
// CIS 2.3.2.2 — Time within appropriate limits (manual)

func init() {
	Register(newCheck(
		"2.3.2.1", "Time set automatically",
		"2", "CIS Benchmark", "Medium",
		"Automatic NTP sync prevents clock skew that can affect authentication and logging.",
		"sudo defaults write /Library/Preferences/com.apple.timezone.auto.plist Active -int 1",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.timezone.auto.plist Active -int 1",
			"System clock will sync automatically with a network time server.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.timezone.auto.plist", "Active")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "Automatic time is not enabled"}
			}
			return Result{StatusPass, "Automatic time sync is active"}
		},
	))

	Register(newCheck(
		"2.3.2.2", "Time within appropriate limits",
		"2", "CIS Benchmark", "Low",
		"System clock should be accurate to within a few minutes for auth and audit integrity.",
		"Verify system time is accurate and NTP is functional.",
		true, nil,
		func() Result { return Result{StatusManual, "Manual review required — verify NTP accuracy"} },
	))
}
