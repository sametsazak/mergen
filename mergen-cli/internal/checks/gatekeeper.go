package checks

// CIS 2.6.3.1 — Diagnostic data sharing disabled
// CIS 2.6.3.2 — Improve Siri & Dictation disabled
// CIS 2.6.3.3 — Improve assistive voice disabled
// CIS 2.6.3.4 — Share with app developers (advisory)
// CIS 2.6.4   — Personalized ads disabled
// CIS 2.6.5   — Gatekeeper enabled
// CIS 2.6.7   — Lockdown Mode (advisory)
// CIS 2.6.8   — Admin password for System Settings (advisory)

func init() {
	Register(newCheck(
		"2.6.3.1", "Diagnostic data sharing disabled",
		"2", "CIS Benchmark", "Low",
		"Sending diagnostics to Apple may reveal sensitive system information.",
		"sudo defaults write '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit -bool false",
		false,
		adminFix(
			"defaults write '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit -bool false",
			"Sending diagnostic and usage data to Apple will be turned off.",
		),
		func() Result {
			out, err := shell("defaults read '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit 2>/dev/null")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Diagnostic data sharing is enabled"}
			}
			return Result{StatusPass, "Diagnostic data sharing is disabled"}
		},
	))

	Register(newCheck(
		"2.6.3.2", "Improve Siri & Dictation disabled",
		"2", "CIS Benchmark", "Low",
		"This setting shares Siri interaction recordings with Apple for model improvement.",
		"defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2",
		false,
		userFix(
			"defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2",
			"Siri & Dictation improvement data sharing will be turned off.",
		),
		func() Result {
			out, err := shell("defaults read com.apple.assistant.support 'Siri Data Sharing Opt-In Status' 2>/dev/null")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Siri data sharing opt-in is enabled"}
			}
			return Result{StatusPass, "Siri data sharing is disabled"}
		},
	))

	Register(newCheck(
		"2.6.3.3", "Improve assistive voice features disabled",
		"2", "CIS Benchmark", "Low",
		"Shares voice recordings with Apple for accessibility model improvement.",
		"defaults write com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled -bool false",
		false,
		userFix(
			"defaults write com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled -bool false",
			"Assistive Voice improvement data sharing will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Accessibility", "AXSAudioDonationSiriImprovementEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Assistive voice improvement sharing is enabled"}
			}
			return Result{StatusPass, "Assistive voice improvement sharing is disabled"}
		},
	))

	Register(newCheck(
		"2.6.3.4", "Share with app developers disabled",
		"2", "CIS Benchmark", "Low",
		"Sharing crash data with app developers may expose system details.",
		"Disable in System Settings > Privacy & Security > Analytics & Improvements.",
		true, nil,
		func() Result { return Result{StatusManual, "Manual review required"} },
	))

	Register(newCheck(
		"2.6.4", "Personalized ads disabled",
		"2", "CIS Benchmark", "Low",
		"Apple personalized advertising builds a profile using your usage data.",
		"defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false",
		false,
		userFix(
			"defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false",
			"Apple personalized advertising will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.AdLib", "allowApplePersonalizedAdvertising")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Personalized advertising is enabled"}
			}
			return Result{StatusPass, "Personalized advertising is disabled"}
		},
	))

	Register(newCheck(
		"2.6.5", "Gatekeeper enabled",
		"2", "CIS Benchmark", "High",
		"Gatekeeper ensures only code-signed, trusted apps can run on this Mac.",
		"sudo spctl --master-enable",
		false,
		adminFix(
			"spctl --master-enable",
			"Gatekeeper will be re-enabled — only apps from identified developers will run.",
		),
		func() Result {
			out, err := shell("spctl --status 2>&1")
			if err == nil && contains(out, "assessments enabled") {
				return Result{StatusPass, "Gatekeeper is enabled"}
			}
			if contains(out, "disabled") {
				return Result{StatusFail, "Gatekeeper is disabled"}
			}
			return Result{StatusWarn, "Could not determine Gatekeeper status: " + out}
		},
	))

	Register(newCheck(
		"2.6.7", "Lockdown Mode (advisory)",
		"2", "CIS Benchmark", "Low",
		"Lockdown Mode provides extreme protection for high-risk individuals.",
		"Enable in System Settings > Privacy & Security > Lockdown Mode.",
		true, nil,
		func() Result { return Result{StatusManual, "Advisory: review whether Lockdown Mode is appropriate"} },
	))

	Register(newCheck(
		"2.6.8", "Admin password required for System Settings",
		"2", "CIS Benchmark", "Medium",
		"Requiring admin authentication prevents unauthorized changes to system preferences.",
		"Enable in System Settings > Privacy & Security.",
		true, nil,
		func() Result { return Result{StatusManual, "Manual review required"} },
	))
}
