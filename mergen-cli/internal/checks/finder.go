package checks

// CIS 5.9   — Guest home folder does not exist
// CIS 6.1.1 — Filename extensions shown in Finder
// CIS 6.1.2 — Home folder permissions

func init() {
	Register(newCheck(
		"5.9", "Guest home folder does not exist",
		"5", "CIS Benchmark", "Low",
		"After disabling the Guest account, the legacy /Users/Guest folder may remain and can be misused.",
		"sudo rm -rf /Users/Guest",
		false, nil,
		func() Result {
			out, err := shell("ls /Users/ 2>/dev/null")
			if err == nil && contains(out, "Guest") {
				return Result{StatusFail, "Guest home folder exists at /Users/Guest"}
			}
			return Result{StatusPass, "Guest home folder does not exist"}
		},
	))

	Register(newCheck(
		"6.1.1", "Filename extensions shown",
		"6", "CIS Benchmark", "Low",
		"Hidden extensions can trick users into running malicious executables disguised as documents.",
		"defaults write NSGlobalDomain AppleShowAllExtensions -bool true",
		false,
		userFix(
			"defaults write NSGlobalDomain AppleShowAllExtensions -bool true",
			"All file extensions will be visible in Finder.",
		),
		func() Result {
			out, err := defaultsRead("NSGlobalDomain", "AppleShowAllExtensions")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "File extensions are hidden (AppleShowAllExtensions = " + out + ")"}
			}
			return Result{StatusPass, "File extensions are shown"}
		},
	))

	Register(newCheck(
		"6.1.2", "Home folder permissions",
		"6", "CIS Benchmark", "Medium",
		"Home folder permissions should prevent other local users from reading your files.",
		"chmod 700 ~/",
		false, nil,
		func() Result {
			out, err := shell("ls -ld ~/ | awk '{print $1}'")
			if err != nil {
				return Result{StatusWarn, "Could not read home folder permissions"}
			}
			if out == "drwx------" || out == "drwx------+" {
				return Result{StatusPass, "Home folder permissions: " + out}
			}
			return Result{StatusFail, "Home folder permissions are too open: " + out + " (should be drwx------)"}
		},
	))
}
