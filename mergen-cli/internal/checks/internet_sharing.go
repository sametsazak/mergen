package checks

// CIS 2.3.3.7 — Internet sharing disabled
// CIS 2.3.3.8 — Content caching disabled
// CIS 2.3.3.9 — Media sharing disabled
// CIS 2.3.3.10 — Bluetooth sharing disabled

func init() {
	Register(newCheck(
		"2.3.3.7", "Internet sharing disabled",
		"2", "CIS Benchmark", "High",
		"Internet sharing turns the Mac into a router, exposing internal network services.",
		"sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict-add Enabled -int 0",
		false,
		adminFix(
			"defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict-add Enabled -int 0",
			"Internet Sharing will be disabled.",
		),
		func() Result {
			out, err := shell("defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null")
			if err == nil && contains(out, "Enabled = 1") {
				return Result{StatusFail, "Internet sharing is enabled"}
			}
			return Result{StatusPass, "Internet sharing is disabled"}
		},
	))

	Register(newCheck(
		"2.3.3.8", "Content caching disabled",
		"2", "CIS Benchmark", "Low",
		"Content caching serves Apple content to other network devices. Disable unless needed.",
		"sudo /usr/bin/AssetCacheManagerUtil deactivate",
		false,
		adminFix(
			"/usr/bin/AssetCacheManagerUtil deactivate 2>/dev/null; true",
			"Content Caching service will be deactivated.",
		),
		func() Result {
			out, err := shell("/usr/bin/AssetCacheManagerUtil status 2>&1")
			if err == nil && contains(out, "activated: true") {
				return Result{StatusFail, "Content caching is active"}
			}
			return Result{StatusPass, "Content caching is not active"}
		},
	))

	Register(newCheck(
		"2.3.3.9", "Media sharing disabled",
		"2", "CIS Benchmark", "Low",
		"Media sharing (Home Sharing) exposes your media library to the local network.",
		"defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0",
		false,
		adminFix(
			"defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0; launchctl stop com.apple.amp.mediasharingd 2>/dev/null; true",
			"Media Sharing service will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.amp.mediasharingd", "home-sharing-enabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Media sharing (Home Sharing) is enabled"}
			}
			return Result{StatusPass, "Media sharing is disabled"}
		},
	))

	Register(newCheck(
		"2.3.3.10", "Bluetooth sharing disabled",
		"2", "CIS Benchmark", "Medium",
		"Bluetooth sharing can expose files to nearby devices without a password.",
		"defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false",
		false,
		userFix(
			"defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false",
			"Bluetooth Sharing will be disabled.",
		),
		func() Result {
			out, err := defaultsReadHost("com.apple.Bluetooth", "PrefKeyServicesEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Bluetooth Sharing is enabled"}
			}
			return Result{StatusPass, "Bluetooth Sharing is disabled"}
		},
	))
}
