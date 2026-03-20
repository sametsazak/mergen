package checks

import "strings"

// Java 6 runtime disabled

func init() {
	Register(newCheck(
		"", "Java 6 runtime disabled",
		"5", "Security", "High",
		"Java 6 is end-of-life and contains unpatched security vulnerabilities. It should not be the active runtime.",
		"Install a supported Java version and remove Java 6.",
		false, nil,
		func() Result {
			out, err := shell("/usr/bin/java -version 2>&1")
			if err != nil || trim(out) == "" {
				return Result{StatusPass, "Java is not installed or not in PATH"}
			}
			if strings.Contains(strings.ToLower(out), "java 1.6") || strings.Contains(strings.ToLower(out), "version \"1.6") {
				return Result{StatusFail, "Java 6 is the active runtime — upgrade immediately: " + trim(out)}
			}
			return Result{StatusPass, "Java version is not 6: " + trim(out)}
		},
	))
}
