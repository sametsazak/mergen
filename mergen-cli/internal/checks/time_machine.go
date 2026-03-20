package checks

// CIS 2.3.4.1 — Time Machine backup enabled
// Time Machine volumes encrypted

func init() {
	Register(newCheck(
		"2.3.4.1", "Time Machine backup enabled",
		"2", "CIS Benchmark", "Medium",
		"Regular backups protect against data loss from ransomware, hardware failure, or accidental deletion.",
		"Enable in System Settings > Time Machine.",
		false, nil,
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.TimeMachine.plist", "AutoBackup")
			if err != nil {
				return Result{StatusFail, "Time Machine plist not found — Time Machine may not be configured"}
			}
			if trim(out) == "1" {
				return Result{StatusPass, "Time Machine automatic backup is enabled"}
			}
			return Result{StatusFail, "Time Machine automatic backup is disabled"}
		},
	))

	Register(newCheck(
		"", "Time Machine volumes encrypted",
		"2", "CIS Benchmark", "Medium",
		"Unencrypted backup volumes expose all data if the backup disk is lost or stolen.",
		"Enable encryption when setting up a Time Machine backup disk.",
		false, nil,
		func() Result {
			out, err := shell("defaults read /Library/Preferences/com.apple.TimeMachine.plist 2>/dev/null")
			if err != nil || trim(out) == "" {
				return Result{StatusWarn, "Could not read Time Machine preferences — Time Machine may not be configured"}
			}
			if contains(out, "NotEncrypted") {
				return Result{StatusFail, "One or more Time Machine volumes are not encrypted"}
			}
			return Result{StatusPass, "Time Machine volumes are encrypted (or no volumes configured)"}
		},
	))
}
