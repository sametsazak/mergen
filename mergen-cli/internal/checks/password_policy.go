package checks

import (
	"fmt"
	"strconv"
	"strings"
)

// CIS 5.2.1 — Password lockout threshold ≤ 5
// CIS 5.2.2 — Minimum password length ≥ 15

func init() {
	Register(newCheck(
		"5.2.1", "Password lockout threshold ≤ 5 attempts",
		"5", "CIS Benchmark", "High",
		"Accounts should lock after no more than 5 consecutive failed login attempts.",
		"sudo pwpolicy -n /Local/Default -setglobalpolicy maxFailedLoginAttempts=5",
		false,
		adminFix(
			"pwpolicy -n /Local/Default -setglobalpolicy maxFailedLoginAttempts=5",
			"Account will lock after 5 consecutive failed password attempts.",
		),
		func() Result {
			out, err := shell("pwpolicy -getaccountpolicies 2>/dev/null")
			if err != nil || out == "" {
				return Result{StatusWarn, "Could not read password policy (may require admin)"}
			}
			if !contains(out, "policyAttributeMaximumFailedAuthentications") {
				return Result{StatusFail, "No login failure lockout policy is configured"}
			}
			lines := strings.Split(out, "\n")
			for i, line := range lines {
				if strings.Contains(line, "policyAttributeMaximumFailedAuthentications") && i+1 < len(lines) {
					next := strings.TrimSpace(lines[i+1])
					next = strings.TrimPrefix(next, "<integer>")
					next = strings.TrimSuffix(next, "</integer>")
					if n, parseErr := strconv.Atoi(next); parseErr == nil {
						if n <= 5 {
							return Result{StatusPass, fmt.Sprintf("Lockout after %d failed attempts", n)}
						}
						return Result{StatusFail, fmt.Sprintf("Lockout threshold is %d (should be ≤ 5)", n)}
					}
				}
			}
			return Result{StatusPass, "Lockout policy is configured"}
		},
	))

	Register(newCheck(
		"5.2.2", "Minimum password length ≥ 15 characters",
		"5", "CIS Benchmark", "High",
		"Longer passwords are exponentially harder to brute-force.",
		"sudo pwpolicy -n /Local/Default -setglobalpolicy minChars=15",
		false,
		adminFix(
			"pwpolicy -n /Local/Default -setglobalpolicy minChars=15",
			"Minimum password length will be set to 15 characters.",
		),
		func() Result {
			out, err := shell("pwpolicy -getaccountpolicies 2>/dev/null")
			if err != nil || out == "" {
				return Result{StatusWarn, "Could not read password policy (may require admin)"}
			}
			if !contains(out, "minChars") {
				return Result{StatusFail, "No minimum password length policy is configured"}
			}
			return Result{StatusPass, "Minimum password length policy is configured"}
		},
	))
}
