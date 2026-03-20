package checks

// CIS 2.6.1.1 — Location services enabled
// CIS 2.6.1.2 — Location services shown in menu bar
// Bluetooth status shown in menu bar

func init() {
	Register(newCheck(
		"2.6.1.1", "Location services enabled",
		"2", "CIS Benchmark", "Low",
		"Location Services are required for time zone accuracy and Find My. This check verifies the location daemon is running.",
		"Enable in System Settings > Privacy & Security > Location Services.",
		false, nil,
		func() Result {
			if launchctlRunning("com.apple.locationd") {
				return Result{StatusPass, "Location Services (locationd) is running"}
			}
			return Result{StatusFail, "Location Services is not running"}
		},
	))

	Register(newCheck(
		"2.6.1.2", "Location services shown in menu bar",
		"2", "CIS Benchmark", "Low",
		"Showing the Location Services icon lets users see when apps are using their location.",
		"Enable in System Settings > Privacy & Security > Location Services > Show in menu bar.",
		false, nil,
		func() Result {
			out, err := defaultsRead("com.apple.systemuiserver", "menuExtras")
			if err == nil && contains(out, "Location.menu") {
				return Result{StatusPass, "Location Services icon is visible in the menu bar"}
			}
			return Result{StatusFail, "Location Services icon is not shown in the menu bar"}
		},
	))

	Register(newCheck(
		"", "Bluetooth status shown in menu bar",
		"2", "CIS Benchmark", "Low",
		"Showing Bluetooth in the menu bar helps users notice unexpected Bluetooth activity.",
		"Enable in System Settings > Control Center > Bluetooth > Show in Menu Bar.",
		false, nil,
		func() Result {
			out, err := defaultsRead("com.apple.controlcenter.plist", "NSStatusItem Visible Bluetooth")
			if err == nil && trim(out) == "1" {
				return Result{StatusPass, "Bluetooth status is shown in the menu bar"}
			}
			return Result{StatusFail, "Bluetooth status is not shown in the menu bar"}
		},
	))
}
