package checks

// CIS 2.1.1.1 — iCloud Keychain disabled (advisory)
// CIS 2.1.1.3 — iCloud Drive Desktop and Documents sync disabled

func init() {
	Register(newCheck(
		"2.1.1.1", "iCloud Keychain disabled",
		"2", "CIS Benchmark", "Medium",
		"iCloud Keychain syncs passwords and credentials across Apple devices, which may violate data residency requirements.",
		"Disable via MDM profile (allowCloudKeychainSync = false) or System Settings > Apple ID > iCloud > Passwords & Keychain.",
		true, nil,
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudKeychainSync').js\" 2>/dev/null")
			if err == nil && trim(out) == "false" {
				return Result{StatusPass, "iCloud Keychain sync is disabled via MDM profile"}
			}
			if err == nil && trim(out) == "true" {
				return Result{StatusFail, "iCloud Keychain sync is enabled via MDM profile"}
			}
			return Result{StatusManual, "Manual review required: check System Settings > Apple ID > iCloud > Passwords & Keychain"}
		},
	))

	Register(newCheck(
		"2.1.1.3", "iCloud Drive Desktop and Documents sync disabled",
		"2", "CIS Benchmark", "Medium",
		"iCloud Drive Desktop/Documents sync automatically uploads sensitive files to cloud storage.",
		"defaults write com.apple.finder FXICloudDriveDesktop -bool false && defaults write com.apple.finder FXICloudDriveDocuments -bool false",
		false,
		userFix(
			"defaults write com.apple.finder FXICloudDriveDesktop -bool false && defaults write com.apple.finder FXICloudDriveDocuments -bool false",
			"iCloud Drive Desktop and Documents sync will be disabled.",
		),
		func() Result {
			desktop, _ := defaultsRead("com.apple.finder", "FXICloudDriveDesktop")
			docs, _ := defaultsRead("com.apple.finder", "FXICloudDriveDocuments")
			if trim(desktop) == "1" || trim(docs) == "1" {
				var which []string
				if trim(desktop) == "1" {
					which = append(which, "Desktop")
				}
				if trim(docs) == "1" {
					which = append(which, "Documents")
				}
				return Result{StatusFail, "iCloud Drive sync enabled for: " + join(which, ", ")}
			}
			return Result{StatusPass, "iCloud Drive Desktop and Documents sync is disabled"}
		},
	))
}
