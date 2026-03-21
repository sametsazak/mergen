package checks

// CIS 4.2 — Apache HTTP server disabled
// CIS 4.3 — NFS server disabled

func init() {
	Register(newCheck(
		"4.2", "Apache HTTP server disabled",
		"4", "CIS Benchmark", "High",
		"The built-in Apache web server should be disabled unless explicitly required.",
		"sudo launchctl disable system/org.apache.httpd",
		false,
		adminFix(
			"launchctl disable system/org.apache.httpd; launchctl stop org.apache.httpd 2>/dev/null; true",
			"Apache HTTP Server will be disabled and stopped.",
		),
		func() Result {
			if launchctlRunning("org.apache.httpd") {
				return Result{StatusFail, "Apache HTTP server is running"}
			}
			return Result{StatusPass, "Apache HTTP server is not running"}
		},
	))

	Register(newCheck(
		"4.3", "NFS server disabled",
		"4", "CIS Benchmark", "High",
		"The NFS daemon exposes the filesystem over the network and should be disabled.",
		"sudo launchctl disable system/com.apple.nfsd",
		false,
		adminFix(
			"launchctl disable system/com.apple.nfsd",
			"NFS file server will be disabled.",
		),
		func() Result {
			if !launchctlDisabled("com.apple.nfsd") {
				return Result{StatusFail, "NFS server is not disabled"}
			}
			return Result{StatusPass, "NFS server is disabled"}
		},
	))
}
