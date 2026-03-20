package checks

// FileVault full-disk encryption
// XProtect malware detection
// CIS 5.10 — XProtect enabled

func init() {
	Register(newCheck(
		"", "FileVault enabled",
		"5", "CIS Benchmark", "Critical",
		"FileVault full-disk encryption protects all data if the device is lost or stolen.",
		"Enable in System Settings > Privacy & Security > FileVault.",
		false, nil,
		func() Result {
			out, err := run("/usr/bin/fdesetup", "status")
			if err != nil {
				return Result{StatusWarn, "Could not query FileVault: " + out}
			}
			if contains(out, "FileVault is On") {
				return Result{StatusPass, "FileVault is enabled"}
			}
			return Result{StatusFail, "FileVault is OFF — disk is not encrypted"}
		},
	))

	Register(newCheck(
		"5.10", "XProtect protection enabled",
		"5", "CIS Benchmark", "High",
		"XProtect is macOS's built-in malware detection and blocking system.",
		"XProtect is managed automatically by Apple and should not be disabled.",
		false, nil,
		func() Result {
			_, err := shell("ls /Library/Apple/System/Library/CoreServices/XProtect.bundle 2>/dev/null")
			if err == nil {
				return Result{StatusPass, "XProtect bundle is present"}
			}
			return Result{StatusWarn, "Could not verify XProtect presence"}
		},
	))

	Register(newCheck(
		"", "Certificate trust settings valid",
		"5", "CIS Benchmark", "Medium",
		"Untrusted root certificates can enable man-in-the-middle attacks.",
		"Review certificate trust settings in Keychain Access > System Roots.",
		true, nil,
		func() Result { return Result{StatusManual, "Manual review required in Keychain Access"} },
	))
}
