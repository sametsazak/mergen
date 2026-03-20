package checks

import "fmt"

// CIS 2.11.1 — Screen saver activates within 20 minutes
// CIS 2.11.2 — Password required on wake

func init() {
	Register(newCheck(
		"2.11.1", "Screen saver activates within 20 minutes",
		"2", "CIS Benchmark", "Medium",
		"An inactivity timeout ensures the screen is locked when the Mac is left unattended.",
		"defaults -currentHost write com.apple.screensaver idleTime -int 1200",
		false,
		userFix(
			"defaults -currentHost write com.apple.screensaver idleTime -int 1200",
			"Screen saver will activate after 20 minutes of inactivity.",
		),
		func() Result {
			out, err := defaultsReadHost("com.apple.screensaver", "idleTime")
			if err != nil {
				out, err = defaultsRead("com.apple.screensaver", "idleTime")
			}
			if err != nil || trim(out) == "0" || trim(out) == "" {
				return Result{StatusFail, "Screen saver idle time is not set (idleTime = " + out + ")"}
			}
			var secs int
			if _, scanErr := fmt.Sscanf(trim(out), "%d", &secs); scanErr == nil {
				if secs > 1200 {
					return Result{StatusFail, fmt.Sprintf("Screen saver timeout is %ds — exceeds 1200s limit", secs)}
				}
				return Result{StatusPass, fmt.Sprintf("Screen saver activates after %d seconds", secs)}
			}
			return Result{StatusWarn, "idleTime = " + out}
		},
	))

	Register(newCheck(
		"2.11.2", "Password required on wake",
		"2", "CIS Benchmark", "High",
		"Requiring a password on wake prevents unauthorized access after the screen locks.",
		"defaults -currentHost write com.apple.screensaver askForPassword -bool true",
		false,
		userFix(
			"defaults -currentHost write com.apple.screensaver askForPassword -bool true && defaults -currentHost write com.apple.screensaver askForPasswordDelay -int 0",
			"Your password will be required immediately when the screen saver or sleep activates.",
		),
		func() Result {
			out, err := defaultsReadHost("com.apple.screensaver", "askForPassword")
			if err != nil {
				out, err = defaultsRead("com.apple.screensaver", "askForPassword")
			}
			if err != nil || trim(out) != "1" {
				return Result{StatusFail, "Password on wake is not required"}
			}
			return Result{StatusPass, "Password required on wake"}
		},
	))
}
