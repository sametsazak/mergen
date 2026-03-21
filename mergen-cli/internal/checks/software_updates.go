package checks

// Section 1 — Software Updates
// CIS IDs: 1.2, 1.3, 1.4, 1.5, 1.6

func init() {
	Register(newCheck(
		"1.2", "Critical updates auto-install enabled",
		"1", "CIS Benchmark", "Medium",
		"Ensures critical security updates install automatically without user interaction.",
		"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -int 1",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -int 1",
			"Critical security updates will install automatically.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "CriticalUpdateInstall is not enabled (got: " + out + ")"}
			}
			return Result{StatusPass, "CriticalUpdateInstall = 1"}
		},
	))

	Register(newCheck(
		"1.3", "Auto-update enabled",
		"1", "CIS Benchmark", "Medium",
		"Ensures macOS downloads updates automatically in the background.",
		"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
			"macOS updates will be downloaded automatically in the background.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "AutomaticDownload is not enabled (got: " + out + ")"}
			}
			return Result{StatusPass, "AutomaticDownload = 1"}
		},
	))

	Register(newCheck(
		"1.4", "App Store auto-updates enabled",
		"1", "CIS Benchmark", "Medium",
		"Ensures App Store application updates are installed automatically.",
		"sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true",
			"App Store application updates will install automatically.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.commerce", "AutoUpdate")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "App Store AutoUpdate is not enabled (got: " + out + ")"}
			}
			return Result{StatusPass, "AutoUpdate = 1"}
		},
	))

	Register(newCheck(
		"1.5", "Security responses auto-install enabled",
		"1", "CIS Benchmark", "High",
		"Ensures security responses and system files install automatically.",
		"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true",
			"Security responses and system files will install automatically.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "ConfigDataInstall is not enabled (got: " + out + ")"}
			}
			return Result{StatusPass, "ConfigDataInstall = 1"}
		},
	))

	Register(newCheck(
		"1.6", "Software update deferment policy",
		"1", "CIS Benchmark", "Low",
		"Checks whether a managed deferment policy is configured for software updates.",
		"sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate enforcedSoftwareUpdateDelay -int 30",
		false, nil,
		func() Result {
			out, _ := defaultsRead("/Library/Preferences/com.apple.SoftwareUpdate", "enforcedSoftwareUpdateDelay")
			if trim(out) == "" || trim(out) == "0" {
				return Result{StatusWarn, "No update deferment policy is configured"}
			}
			return Result{StatusPass, "Update deferment delay = " + out + " days"}
		},
	))
}
