package checks

// CIS 2.3.1.1 — AirDrop disabled
// CIS 2.3.1.2 — AirPlay Receiver disabled

func init() {
	Register(newCheck(
		"2.3.1.1", "AirDrop disabled",
		"2", "CIS Benchmark", "Medium",
		"AirDrop can expose files to nearby devices without authentication.",
		"defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES",
		false,
		userFix(
			"defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES",
			"AirDrop will be disabled for all networks.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.NetworkBrowser", "DisableAirDrop")
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "AirDrop is enabled (DisableAirDrop = " + out + ")"}
			}
			return Result{StatusPass, "AirDrop is disabled"}
		},
	))

	Register(newCheck(
		"2.3.1.2", "AirPlay Receiver disabled",
		"2", "CIS Benchmark", "Low",
		"AirPlay Receiver allows other devices to cast content to this Mac.",
		"defaults write com.apple.controlcenter AirplayRecieverEnabled -int 0",
		false,
		userFix(
			"defaults write com.apple.controlcenter AirplayRecieverEnabled -int 0",
			"AirPlay Receiver will be off — other devices can no longer cast to this Mac.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.controlcenter", "AirplayRecieverEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "AirPlay Receiver is enabled"}
			}
			return Result{StatusPass, "AirPlay Receiver is disabled"}
		},
	))
}
