package checks

// CIS 2.3.3.3 — Printer sharing disabled

func init() {
	Register(newCheck(
		"2.3.3.3", "Printer sharing disabled",
		"2", "CIS Benchmark", "Low",
		"Printer sharing exposes CUPS to the network and should be off unless required.",
		"sudo cupsctl --no-share-printers",
		false,
		adminFix(
			"cupsctl --no-share-printers",
			"Printer Sharing will be turned off.",
		),
		func() Result {
			out, err := shell("cupsctl 2>/dev/null | grep _share_printers")
			if err == nil && contains(out, "_share_printers=1") {
				return Result{StatusFail, "Printer sharing is enabled"}
			}
			return Result{StatusPass, "Printer sharing is disabled"}
		},
	))
}
