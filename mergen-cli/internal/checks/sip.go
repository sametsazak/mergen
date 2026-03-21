package checks

// CIS 5.1.1 — System Integrity Protection enabled
// CIS 5.1.3 — AMFI enabled
// CIS 5.1.4 — Signed System Volume enabled

func init() {
	Register(newCheck(
		"5.1.1", "System Integrity Protection enabled",
		"5", "CIS Benchmark", "Critical",
		"SIP prevents malware and users from modifying protected system files and directories.",
		"SIP can only be re-enabled from Recovery Mode: csrutil enable",
		false, nil,
		func() Result {
			out, err := run("/usr/bin/csrutil", "status")
			if err != nil {
				return Result{StatusWarn, "Could not run csrutil: " + out}
			}
			if contains(out, "enabled") {
				return Result{StatusPass, "SIP is enabled"}
			}
			return Result{StatusFail, "SIP is disabled — " + out}
		},
	))

	Register(newCheck(
		"5.1.3", "AMFI (Apple Mobile File Integrity) enabled",
		"5", "CIS Benchmark", "Critical",
		"AMFI enforces code signing validation and prevents unsigned code from executing.",
		"Remove amfi_get_out_of_my_way=1 from NVRAM boot-args (requires Recovery Mode).",
		false, nil,
		func() Result {
			out, err := run("/usr/sbin/nvram", "-p")
			if err != nil {
				return Result{StatusWarn, "Could not read NVRAM: " + out}
			}
			if contains(out, "amfi_get_out_of_my_way=1") {
				return Result{StatusFail, "AMFI is disabled via NVRAM boot-args"}
			}
			return Result{StatusPass, "AMFI is enabled"}
		},
	))

	Register(newCheck(
		"5.1.4", "Signed System Volume (SSV) enabled",
		"5", "CIS Benchmark", "Critical",
		"SSV cryptographically seals the macOS system volume to detect tampering.",
		"SSV can only be re-enabled from Recovery Mode.",
		false, nil,
		func() Result {
			out, err := run("/usr/bin/csrutil", "authenticated-root", "status")
			if err != nil {
				return Result{StatusWarn, "Could not query SSV status: " + out}
			}
			if contains(out, "enabled") {
				return Result{StatusPass, "Signed System Volume is enabled"}
			}
			return Result{StatusFail, "SSV is disabled"}
		},
	))
}
