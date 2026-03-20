package checks

// CIS 2.7.1 — Screen saver corners configured

func init() {
	Register(newCheck(
		"2.7.1", "Screen saver corners configured",
		"2", "CIS Benchmark", "Low",
		"A hot corner set to 'Disable Screen Saver' (value 6) lets anyone bypass the lock screen by moving the mouse.",
		"Remove any hot corner set to 'Disable Screen Saver' in System Settings > Desktop & Screen Saver > Hot Corners.",
		false, nil,
		func() Result {
			cornerKeys := []string{"wvous-tl-corner", "wvous-tr-corner", "wvous-bl-corner", "wvous-br-corner"}
			for _, key := range cornerKeys {
				val, err := defaultsRead("com.apple.dock", key)
				if err == nil && trim(val) == "6" {
					return Result{StatusFail, "Hot corner '" + key + "' is set to 'Disable Screen Saver' — bypasses lock screen"}
				}
			}
			return Result{StatusPass, "No hot corner is configured to disable the screen saver"}
		},
	))
}
