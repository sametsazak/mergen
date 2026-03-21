package checks

import "strings"

// CIS 2.8.1   — Universal Control disabled
// CIS 2.9.1   — Spotlight suggestions (advisory)
// CIS 2.10.1.2 — Sleep enabled (Apple Silicon)
// CIS 2.10.2  — Power Nap disabled
// CIS 2.10.3  — Wake for network access disabled

func init() {
	Register(newCheck(
		"2.8.1", "Universal Control disabled",
		"2", "CIS Benchmark", "Low",
		"Universal Control shares keyboard and mouse across nearby Apple devices.",
		"defaults -currentHost write com.apple.universalcontrol Disable -int 1",
		false,
		userFix(
			"defaults -currentHost write com.apple.universalcontrol Disable -int 1",
			"Universal Control will be disabled.",
		),
		func() Result {
			out, err := defaultsReadHost("com.apple.universalcontrol", "Disable")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "Universal Control is not disabled"}
			}
			return Result{StatusPass, "Universal Control is disabled"}
		},
	))

	Register(newCheck(
		"2.9.1", "Spotlight search query sharing disabled",
		"2", "CIS Benchmark", "Low",
		"Spotlight can send search queries to Apple servers for improved suggestions.",
		"Deploy MDM profile with 'Search Queries Data Sharing Status' = 2, or disable in System Settings > Siri & Spotlight.",
		false,
		userFix(
			"defaults write com.apple.assistant.support 'Search Queries Data Sharing Status' -int 2",
			"Spotlight search query sharing will be disabled.",
		),
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support').objectForKey('Search Queries Data Sharing Status').js\" 2>/dev/null")
			if err == nil && trim(out) == "2" {
				return Result{StatusPass, "Spotlight search query sharing is disabled"}
			}
			// Fall back to direct defaults read
			out2, _ := defaultsRead("com.apple.assistant.support", "Search Queries Data Sharing Status")
			if trim(out2) == "2" {
				return Result{StatusPass, "Spotlight search query sharing is disabled"}
			}
			if trim(out2) == "1" || trim(out) == "1" {
				return Result{StatusFail, "Spotlight search query sharing is enabled"}
			}
			return Result{StatusWarn, "Spotlight search query sharing status could not be determined"}
		},
	))

	Register(newCheck(
		"2.10.1.2", "Sleep enabled (Apple Silicon)",
		"2", "CIS Benchmark", "Medium",
		"Sleep should be enabled so the screen locks automatically during inactivity.",
		"sudo pmset -a sleep 15 && sudo pmset -a displaysleep 10",
		false,
		adminFix(
			"pmset -a sleep 15 && pmset -a displaysleep 10",
			"Sleep will be set to 15 min and display sleep to 10 min.",
		),
		func() Result {
			cpu, _ := run("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
			if strings.Contains(cpu, "Intel") {
				return Result{StatusPass, "Not applicable — Apple Silicon only (detected Intel CPU)"}
			}
			out, err := shell("pmset -b -g 2>/dev/null | grep -E '^ sleep|^ displaysleep'")
			if err != nil || out == "" {
				return Result{StatusFail, "Sleep and display sleep are not configured"}
			}
			return Result{StatusPass, "Power settings: " + strings.ReplaceAll(out, "\n", ", ")}
		},
	))

	Register(newCheck(
		"2.10.2", "Power Nap disabled (Intel Macs only)",
		"2", "CIS Benchmark", "Low",
		"Power Nap allows the Mac to perform tasks while asleep, increasing the attack surface. This setting only applies to Intel Macs.",
		"sudo pmset -a powernap 0",
		false,
		adminFix(
			"pmset -a powernap 0 && pmset -a darkwakes 0",
			"Power Nap and dark wake will be disabled.",
		),
		func() Result {
			cpu, _ := run("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
			if !strings.Contains(cpu, "Intel") {
				return Result{StatusPass, "Not applicable — this check is for Intel Macs only"}
			}
			out, err := shell("pmset -g custom 2>/dev/null | grep powernap")
			if err != nil {
				return Result{StatusWarn, "Could not read power settings"}
			}
			if contains(out, "1") {
				return Result{StatusFail, "Power Nap is enabled"}
			}
			return Result{StatusPass, "Power Nap is disabled"}
		},
	))

	Register(newCheck(
		"2.10.3", "Wake for network access disabled",
		"2", "CIS Benchmark", "Low",
		"Wake for network access allows remote power-on which can be exploited.",
		"sudo pmset -a womp 0",
		false,
		adminFix(
			"pmset -a womp 0",
			"Wake for network access will be disabled.",
		),
		func() Result {
			out, err := shell("pmset -g custom 2>/dev/null | grep womp")
			if err != nil || trim(out) == "" {
				return Result{StatusWarn, "Could not determine wake for network access setting"}
			}
			if contains(out, "1") {
				return Result{StatusFail, "Wake for network access is enabled"}
			}
			return Result{StatusPass, "Wake for network access is disabled"}
		},
	))
}
