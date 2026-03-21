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
		"5.10", "XProtect is running and updated",
		"5", "CIS Benchmark", "High",
		"XProtect is macOS's built-in malware detection and blocking system.",
		"XProtect is managed automatically by Apple and should not be disabled.",
		false, nil,
		func() Result {
			out, err := run("/usr/bin/xprotect", "status")
			if err == nil && contains(out, "enabled: true") {
				return Result{StatusPass, "XProtect is running and up to date"}
			}
			// Fall back to checking launchctl service
			svc, serr := run("/bin/launchctl", "list", "com.apple.XProtect.daemon.scan")
			if serr == nil && contains(svc, "com.apple.XProtect") {
				return Result{StatusPass, "XProtect daemon is running"}
			}
			return Result{StatusWarn, "Could not verify XProtect status"}
		},
	))

	Register(newCheck(
		"", "Certificate trust settings valid",
		"5", "Security", "High",
		"Untrusted root certificates can enable man-in-the-middle attacks.",
		"Review certificate trust settings in Keychain Access > System Roots.",
		false, nil,
		func() Result {
			out, err := shell("security dump-trust-settings 2>&1")
			if err != nil {
				return Result{StatusWarn, "Could not query certificate trust settings"}
			}
			if contains(out, "No Trust Settings were found") {
				return Result{StatusPass, "No custom certificate trust overrides found"}
			}
			return Result{StatusFail, "Custom certificate trust settings exist — review in Keychain Access"}
		},
	))
}
