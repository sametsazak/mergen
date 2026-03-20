package checks

// CIS 6.4.1 — Terminal secure keyboard entry enabled

func init() {
	Register(newCheck(
		"6.4.1", "Terminal secure keyboard entry enabled",
		"6", "CIS Benchmark", "Medium",
		"Secure keyboard entry prevents other apps from intercepting keystrokes in Terminal.",
		"defaults write com.apple.Terminal SecureKeyboardEntry -bool true",
		false,
		userFix(
			"defaults write com.apple.Terminal SecureKeyboardEntry -bool true",
			"Terminal secure keyboard entry will be enabled, blocking other apps from reading keystrokes.",
		),
		func() Result {
			// Try JS bridge first (most reliable on modern macOS)
			out, err := run("/usr/bin/osascript", "-l", "JavaScript", "-e",
				"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal').objectForKey('SecureKeyboardEntry').js")
			if err == nil {
				if trim(out) == "true" || trim(out) == "1" {
					return Result{StatusPass, "Secure keyboard entry is enabled"}
				}
				return Result{StatusFail, "Secure keyboard entry is disabled"}
			}
			// Fallback to defaults read
			out2, err2 := defaultsRead("com.apple.Terminal", "SecureKeyboardEntry")
			if err2 != nil || trim(out2) != "1" {
				return Result{StatusFail, "Secure keyboard entry is disabled (value: " + out2 + ")"}
			}
			return Result{StatusPass, "Secure keyboard entry is enabled"}
		},
	))
}
