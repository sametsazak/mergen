package checks

// CIS 6.3.1  — Safari auto-open safe files disabled
// CIS 6.3.3  — Safari fraudulent website warning enabled
// CIS 6.3.4  — Safari cross-site tracking prevention enabled
// CIS 6.3.6  — Safari advertising privacy (Private Click Measurement)
// CIS 6.3.8  — Safari internet plugins disabled
// CIS 6.3.10 — Safari status bar shown

func init() {
	Register(newCheck(
		"6.3.1", "Safari auto-open safe files disabled",
		"6", "CIS Benchmark", "Medium",
		"Auto-opening downloaded files can execute malicious content without user confirmation.",
		"defaults write com.apple.Safari AutoOpenSafeDownloads -bool false",
		false,
		userFix(
			"defaults write com.apple.Safari AutoOpenSafeDownloads -bool false",
			"Safari will no longer automatically open downloaded files considered safe.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "AutoOpenSafeDownloads")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Safari auto-opens safe downloads"}
			}
			return Result{StatusPass, "Safari auto-open safe downloads is disabled"}
		},
	))

	Register(newCheck(
		"6.3.3", "Safari fraudulent website warning enabled",
		"6", "CIS Benchmark", "Medium",
		"Safari should warn users when visiting known phishing or malware sites.",
		"defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true",
		false,
		userFix(
			"defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true",
			"Safari fraudulent website warning will be enabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "WarnAboutFraudulentWebsites")
			if err == nil && trim(out) == "1" {
				return Result{StatusPass, "Safari fraudulent website warning is enabled"}
			}
			if err == nil && trim(out) == "0" {
				return Result{StatusFail, "Safari fraud warning is disabled"}
			}
			return Result{StatusWarn, "Safari fraud warning state unknown (default is enabled)"}
		},
	))

	Register(newCheck(
		"6.3.4", "Safari cross-site tracking prevention enabled",
		"6", "CIS Benchmark", "Medium",
		"Prevents advertisers from tracking users across websites via storage APIs.",
		"defaults write com.apple.Safari BlockStoragePolicy -int 2",
		false,
		userFix(
			"defaults write com.apple.Safari BlockStoragePolicy -int 2",
			"Safari cross-site tracking prevention will be enabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "BlockStoragePolicy")
			if err == nil && trim(out) == "2" {
				return Result{StatusPass, "Cross-site tracking prevention is enabled"}
			}
			return Result{StatusWarn, "Safari cross-site tracking prevention is not fully configured (BlockStoragePolicy = " + trim(out) + ")"}
		},
	))

	Register(newCheck(
		"6.3.6", "Safari advertising privacy enabled",
		"6", "CIS Benchmark", "Low",
		"Private Click Measurement is Apple's privacy-preserving ad attribution standard.",
		"defaults write com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled -bool true",
		false,
		userFix(
			"defaults write com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled -bool true",
			"Safari Private Click Measurement (ad privacy) will be enabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "WebKitPreferences.privateClickMeasurementEnabled")
			if err == nil && trim(out) == "0" {
				return Result{StatusFail, "Private Click Measurement is disabled"}
			}
			return Result{StatusPass, "Private Click Measurement is enabled"}
		},
	))

	Register(newCheck(
		"6.3.8", "Safari internet plugins disabled",
		"6", "CIS Benchmark", "Medium",
		"Browser plugins (Java, Flash, Silverlight) are common attack vectors and should be blocked.",
		"defaults write com.apple.Safari PlugInFirstVisitPolicy -int 2",
		false,
		userFix(
			"defaults write com.apple.Safari PlugInFirstVisitPolicy -int 2",
			"Safari will block internet plugins by default.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "PlugInFirstVisitPolicy")
			if err == nil && trim(out) == "2" {
				return Result{StatusPass, "Safari internet plugins are disabled"}
			}
			return Result{StatusFail, "Safari internet plugins are not blocked"}
		},
	))

	Register(newCheck(
		"6.3.10", "Safari status bar shown",
		"6", "CIS Benchmark", "Low",
		"The status bar shows link destinations on hover, helping detect phishing URLs.",
		"defaults write com.apple.Safari ShowOverlayStatusBar -bool true",
		false,
		userFix(
			"defaults write com.apple.Safari ShowOverlayStatusBar -bool true",
			"Safari status bar will be shown, displaying link URLs on hover.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Safari", "ShowOverlayStatusBar")
			if err == nil && trim(out) == "1" {
				return Result{StatusPass, "Safari status bar is shown"}
			}
			if err == nil && trim(out) == "0" {
				return Result{StatusFail, "Safari status bar is hidden"}
			}
			return Result{StatusWarn, "Safari status bar state unknown"}
		},
	))
}
