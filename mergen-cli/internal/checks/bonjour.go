package checks

// CIS 4.1 — Bonjour advertising disabled

func init() {
	Register(newCheck(
		"4.1", "Bonjour advertising disabled",
		"4", "CIS Benchmark", "Low",
		"Bonjour multicast advertising broadcasts service presence to the local network.",
		"sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true",
		false,
		adminFix(
			"defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true",
			"Bonjour multicast advertising will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("/Library/Preferences/com.apple.mDNSResponder.plist", "NoMulticastAdvertisements")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "Bonjour advertising is enabled (NoMulticastAdvertisements = " + out + ")"}
			}
			return Result{StatusPass, "Bonjour advertising is disabled"}
		},
	))
}
