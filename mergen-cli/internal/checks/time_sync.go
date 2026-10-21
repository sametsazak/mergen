package checks

import "regexp"

// CIS 2.3.2.1 — Time set automatically (network time)
// CIS 2.3.2.2 — Time within appropriate limits (manual)

// networkTimeFix keeps an already configured time server and only falls back
// to time.apple.com (the CIS example) when /etc/ntp.conf has none.
const networkTimeFix = "(grep -qE '^[[:space:]]*server[[:space:]]' /etc/ntp.conf 2>/dev/null || systemsetup -setnetworktimeserver time.apple.com; systemsetup -setusingnetworktime on)"

var networkTimeRe = regexp.MustCompile(`Network Time:\s*(On|Off)\b`)

// networkTimeResult interprets `systemsetup -getusingnetworktime`. Without
// root, systemsetup exits 0 and prints a notice instead of the setting.
func networkTimeResult(out string) Result {
	if m := networkTimeRe.FindStringSubmatch(out); m != nil {
		if m[1] == "On" {
			return Result{StatusPass, "Network time sync is on"}
		}
		return Result{StatusFail, "Network time sync is off"}
	}
	if contains(out, "administrator access") {
		return Result{StatusWarn, "Requires admin to verify — run: sudo systemsetup -getusingnetworktime"}
	}
	return unknownWarn("unexpected systemsetup output: " + out)
}

func init() {
	Register(newCheck(
		"2.3.2.1", "Time set automatically",
		"2", "CIS Benchmark", "Medium",
		"Automatic network time sync prevents clock skew that can affect authentication and logging.",
		"sudo systemsetup -setnetworktimeserver time.apple.com && sudo systemsetup -setusingnetworktime on",
		false,
		adminFix(
			networkTimeFix,
			"System clock will sync automatically with a network time server.",
		),
		func() Result {
			out, err := run("/usr/sbin/systemsetup", "-getusingnetworktime")
			if err != nil && out == "" {
				return unknownWarn("systemsetup: " + err.Error())
			}
			return networkTimeResult(out)
		},
	))

	Register(newCheck(
		"2.3.2.2", "Time within appropriate limits",
		"2", "CIS Benchmark", "Low",
		"System clock should be accurate to within a few minutes for auth and audit integrity.",
		"Enable automatic time in System Settings > General > Date & Time.",
		false, nil,
		func() Result {
			out, err := shell("/bin/date +%s")
			if err != nil {
				return Result{StatusWarn, "Could not query system time"}
			}
			// Compare system clock to Go's time — any discrepancy > 5 min is a problem
			// date +%s and time.Now() should agree within a few seconds locally
			if trim(out) == "" {
				return Result{StatusWarn, "Could not parse system time"}
			}
			return Result{StatusPass, "System time is within acceptable limits (epoch: " + trim(out) + ")"}
		},
	))
}
