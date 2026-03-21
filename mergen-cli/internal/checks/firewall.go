package checks

// CIS 2.2.1 — Firewall enabled
// CIS 2.2.2 — Firewall stealth mode enabled

func init() {
	Register(newCheck(
		"2.2.1", "Firewall enabled",
		"2", "CIS Benchmark", "High",
		"The macOS Application Firewall blocks unauthorized incoming connections.",
		"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
		false,
		adminFix(
			"/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
			"macOS Application Firewall will be turned on.",
		),
		func() Result {
			out, err := run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
			if err != nil {
				return Result{StatusWarn, "Could not query firewall state: " + out}
			}
			if contains(out, "enabled") {
				return Result{StatusPass, "Firewall is enabled"}
			}
			return Result{StatusFail, "Firewall is disabled"}
		},
	))

	Register(newCheck(
		"2.2.2", "Firewall stealth mode enabled",
		"2", "CIS Benchmark", "Medium",
		"Stealth mode prevents the Mac from responding to ping and port scan probes.",
		"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
		false,
		adminFix(
			"/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
			"Firewall stealth mode will be enabled — your Mac will not respond to ping or port scans.",
		),
		func() Result {
			out, err := run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
			if err != nil {
				return Result{StatusWarn, "Could not query stealth mode: " + out}
			}
			if contains(out, "enabled") {
				return Result{StatusPass, "Stealth mode is enabled"}
			}
			return Result{StatusFail, "Stealth mode is disabled"}
		},
	))
}
