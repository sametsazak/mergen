package checks

import "strings"

// EFI firmware version check (Intel only)

func init() {
	Register(newCheck(
		"", "EFI firmware version valid",
		"5", "CIS Benchmark", "Medium",
		"Outdated EFI firmware exposes the system to firmware-level attacks that persist across OS reinstalls.",
		"Apply all available firmware updates via Software Update.",
		false, nil,
		func() Result {
			cpu, _ := run("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
			if strings.Contains(cpu, "Apple") || !strings.Contains(cpu, "Intel") {
				return Result{StatusWarn, "EFI check applies to Intel Macs only (detected Apple Silicon)"}
			}
			out, err := run("/usr/sbin/system_profiler", "SPHardwareDataType")
			if err != nil {
				return Result{StatusWarn, "Could not query system hardware information"}
			}
			if strings.Contains(out, "boot_rom_version") || strings.Contains(out, "Boot ROM Version") {
				if strings.Contains(strings.ToUpper(out), "MM71") || strings.Contains(strings.ToUpper(out), "MM81") {
					return Result{StatusFail, "EFI firmware version may be outdated — apply all firmware updates"}
				}
				return Result{StatusPass, "EFI firmware version appears current"}
			}
			return Result{StatusWarn, "Could not determine EFI firmware version"}
		},
	))
}
