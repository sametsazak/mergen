package checks

// CIS 2.11.3 — Login window message (advisory)
// CIS 2.11.4 — Login window shows name and password fields
// CIS 2.11.5 — Password hints disabled
// CIS 2.13.1 — Guest login disabled
// CIS 2.13.2 — Guest access to shared folders disabled
// CIS 2.13.3 — Automatic login disabled

func init() {
	Register(newCheck(
		"2.11.3", "Login window message configured",
		"2", "CIS Benchmark", "Low",
		"A login window message communicates security policy to users at the login screen.",
		"sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText 'Authorized use only'",
		false, nil,
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.loginwindow", "LoginwindowText")
			if err != nil || trim(out) == "" {
				return Result{StatusWarn, "No login window message is configured"}
			}
			return Result{StatusPass, "Login window message: " + out}
		},
	))

	Register(newCheck(
		"2.11.4", "Login window shows name and password fields",
		"2", "CIS Benchmark", "Low",
		"Showing the user list at login leaks account names to anyone at the keyboard.",
		"sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true",
			"Login window will show username and password fields instead of a user list.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "Login window shows user list (SHOWFULLNAME = " + out + ")"}
			}
			return Result{StatusPass, "Login window shows name and password fields"}
		},
	))

	Register(newCheck(
		"2.11.5", "Password hints disabled",
		"2", "CIS Benchmark", "Medium",
		"Password hints after failed logins can help an attacker guess the password.",
		"sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0",
			"Password hints will no longer appear after failed login attempts.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint")
			if err == nil && trim(out) != "0" && trim(out) != "" {
				return Result{StatusFail, "Password hints shown after " + out + " failed attempts"}
			}
			return Result{StatusPass, "Password hints are disabled"}
		},
	))

	Register(newCheck(
		"2.13.1", "Guest login disabled",
		"2", "CIS Benchmark", "High",
		"The Guest account allows login without credentials, bypassing all authentication.",
		"sudo defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false",
			"Guest account will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.loginwindow.plist", "GuestEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Guest login is enabled"}
			}
			return Result{StatusPass, "Guest login is disabled"}
		},
	))

	Register(newCheck(
		"2.13.2", "Guest access to shared folders disabled",
		"2", "CIS Benchmark", "Medium",
		"Guests can read shared folders without any authentication when this is enabled.",
		"sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -int 0",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -int 0",
			"Guest access to shared folders will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.AppleFileServer", "guestAccess")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Guest access to shared folders is enabled"}
			}
			return Result{StatusPass, "Guest access to shared folders is disabled"}
		},
	))

	Register(newCheck(
		"2.13.3", "Automatic login disabled",
		"2", "CIS Benchmark", "High",
		"Automatic login bypasses the password requirement entirely at startup.",
		"sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
		false,
		adminFix(
			"defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null; true",
			"Automatic login will be disabled — a password will be required at every startup.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
			if err == nil && trim(out) != "" {
				return Result{StatusFail, "Automatic login is enabled for: " + out}
			}
			return Result{StatusPass, "Automatic login is disabled"}
		},
	))
}
