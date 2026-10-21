package checks

import "strings"

// CIS 2.3.3.5 — Remote Management (ARD) disabled
// CIS 2.3.3.6 — Remote Apple Events disabled

// ardAgentPath is the process that runs while Remote Management is on.
const ardAgentPath = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"

// ardAgentRunning reports whether `ps -ef` output lists the ARDAgent process.
func ardAgentRunning(ps string) bool {
	return strings.Contains(ps, ardAgentPath)
}

func init() {
	Register(newCheck(
		"2.3.3.5", "Remote management disabled",
		"2", "CIS Benchmark", "High",
		"Remote Management (ARD/VNC) provides privileged remote access. Disable unless needed.",
		"sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
		false,
		adminFix(
			"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null; true",
			"Remote Management (ARD) will be deactivated and stopped.",
		),
		func() Result {
			out, err := run("/bin/ps", "-ef")
			if err != nil {
				return unknownWarn("ps -ef: " + err.Error())
			}
			if ardAgentRunning(out) {
				return Result{StatusFail, "Remote Management (ARDAgent) is running"}
			}
			return Result{StatusPass, "Remote Management is not running"}
		},
	))

	Register(newCheck(
		"2.3.3.6", "Remote Apple Events disabled",
		"2", "CIS Benchmark", "Medium",
		"Remote Apple Events allows other machines to control this Mac via AppleScript.",
		"sudo launchctl disable system/com.apple.AEServer",
		false,
		adminFix(
			"launchctl disable system/com.apple.AEServer; launchctl stop com.apple.AEServer 2>/dev/null; true",
			"Remote Apple Events will be disabled.",
		),
		func() Result {
			if !launchctlDisabled("com.apple.AEServer") {
				return Result{StatusFail, "Remote Apple Events (AEServer) is not disabled"}
			}
			return Result{StatusPass, "Remote Apple Events is disabled"}
		},
	))
}
