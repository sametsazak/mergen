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
				if trim(out) == "true" {
					return Result{StatusPass, "Secure keyboard entry is enabled"}
				}
				if trim(out) == "false" {
					return Result{StatusFail, "Secure keyboard entry is disabled"}
				}
				// Neither true nor false — fall through to defaults
			}
			// Fallback to defaults read
			out2, _ := defaultsRead("com.apple.Terminal", "SecureKeyboardEntry")
			if trim(out2) == "1" {
				return Result{StatusPass, "Secure keyboard entry is enabled"}
			}
			if trim(out2) == "0" {
				return Result{StatusFail, "Secure keyboard entry is disabled"}
			}
			return Result{StatusWarn, "Secure keyboard entry state unknown"}
		},
	))
}
