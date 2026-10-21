package checks

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// CIS 5.2.1 — Password lockout threshold ≤ 5
// CIS 5.2.2 — Minimum password length ≥ 15

var (
	// policyAttributePassword matches '.{15,}' — with an optional ? or + quantifier.
	minLengthPredicateRe = regexp.MustCompile(`policyAttributePassword matches '\.\{(\d+),\}[?+]?'`)
	// Policy parameters, used when no length predicate is present.
	minLengthParamRes = []*regexp.Regexp{
		regexp.MustCompile(`minimumLength\D+(\d+)`),
		regexp.MustCompile(`minChars\D+(\d+)`),
	}
)

// passwordMinLength returns the effective minimum length in
// `pwpolicy -getaccountpolicies` output, with the same rules as
// PasswordMinLengthCheck.swift: the largest `.{N,}` predicate, else the
// largest minimumLength / minChars parameter.
func passwordMinLength(out string) (int, bool) {
	lengths := submatchInts(minLengthPredicateRe, out)
	if len(lengths) == 0 {
		for _, re := range minLengthParamRes {
			lengths = append(lengths, submatchInts(re, out)...)
		}
	}
	if len(lengths) == 0 {
		return 0, false
	}
	return slices.Max(lengths), true
}

// submatchInts returns the first capture group of every match of re in s.
func submatchInts(re *regexp.Regexp, s string) []int {
	var ns []int
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ns = append(ns, n)
		}
	}
	return ns
}

func passwordMinLengthResult(out string) Result {
	n, ok := passwordMinLength(out)
	switch {
	case ok && n >= 15:
		return Result{StatusPass, fmt.Sprintf("Minimum password length is %d", n)}
	case ok:
		return Result{StatusFail, fmt.Sprintf("Minimum password length is %d (should be ≥ 15)", n)}
	case contains(out, "policyAttributePassword matches") || contains(out, "minimumLength") || contains(out, "minChars"):
		return Result{StatusWarn, "Password length policy found but its minimum could not be parsed"}
	}
	return Result{StatusFail, "No minimum password length policy is configured"}
}

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
			return passwordMinLengthResult(out)
		},
	))
}
