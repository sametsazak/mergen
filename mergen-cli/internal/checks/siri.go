package checks

// CIS 2.5.1.1 — Apple Intelligence External Extensions disabled
// CIS 2.5.1.2 — Apple Intelligence Writing Tools disabled
// CIS 2.5.1.3 — Apple Intelligence Mail Summarization disabled
// CIS 2.5.1.4 — Apple Intelligence Notes Summarization disabled
// CIS 2.5.2.1 — Siri disabled

func init() {
	Register(newCheck(
		"2.5.1.1", "Apple Intelligence external extensions disabled",
		"2", "CIS Benchmark", "Medium",
		"External Intelligence Extensions can send data to third-party AI providers like ChatGPT.",
		"Deploy MDM profile with allowExternalIntelligenceIntegrations = false.",
		false, nil,
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowExternalIntelligenceIntegrations').js\" 2>/dev/null")
			if err == nil && trim(out) == "false" {
				return Result{StatusPass, "External Intelligence Extensions are disabled via MDM"}
			}
			if err == nil && trim(out) == "true" {
				return Result{StatusFail, "External Intelligence Extensions are enabled via MDM"}
			}
			return Result{StatusWarn, "No MDM profile found — External Intelligence Extensions state unknown"}
		},
	))

	Register(newCheck(
		"2.5.1.2", "Apple Intelligence Writing Tools disabled",
		"2", "CIS Benchmark", "Medium",
		"Writing Tools may send text content off-device for AI processing.",
		"Deploy MDM profile with allowWritingTools = false.",
		false, nil,
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowWritingTools').js\" 2>/dev/null")
			if err == nil && trim(out) == "false" {
				return Result{StatusPass, "Writing Tools are disabled via MDM"}
			}
			if err == nil && trim(out) == "true" {
				return Result{StatusFail, "Writing Tools are enabled via MDM"}
			}
			return Result{StatusWarn, "No MDM profile found — Writing Tools state unknown"}
		},
	))

	Register(newCheck(
		"2.5.1.3", "Apple Intelligence Mail Summarization disabled",
		"2", "CIS Benchmark", "Medium",
		"Mail Summarization sends email content to AI services, which may violate data privacy policies.",
		"Deploy MDM profile with allowMailSummary = false.",
		false, nil,
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowMailSummary').js\" 2>/dev/null")
			if err == nil && trim(out) == "false" {
				return Result{StatusPass, "Mail Summarization is disabled via MDM"}
			}
			if err == nil && trim(out) == "true" {
				return Result{StatusFail, "Mail Summarization is enabled via MDM"}
			}
			return Result{StatusWarn, "No MDM profile found — Mail Summarization state unknown"}
		},
	))

	Register(newCheck(
		"2.5.1.4", "Apple Intelligence Notes Summarization disabled",
		"2", "CIS Benchmark", "Medium",
		"Notes Summarization may process audio recordings and notes content externally.",
		"Deploy MDM profile with allowNotesTranscription = false.",
		false, nil,
		func() Result {
			out, err := shell("osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowNotesTranscription').js\" 2>/dev/null")
			if err == nil && trim(out) == "false" {
				return Result{StatusPass, "Notes Summarization is disabled via MDM"}
			}
			if err == nil && trim(out) == "true" {
				return Result{StatusFail, "Notes Summarization is enabled via MDM"}
			}
			return Result{StatusWarn, "No MDM profile found — Notes Summarization state unknown"}
		},
	))

	Register(newCheck(
		"2.5.2.1", "Siri disabled",
		"2", "CIS Benchmark", "Low",
		"Siri transmits queries and context to Apple servers.",
		"defaults write com.apple.Siri SiriProfessionalEnabled -bool false",
		false,
		userFix(
			"defaults write com.apple.Siri SiriProfessionalEnabled -bool false",
			"Siri will be disabled.",
		),
		func() Result {
			out, err := defaultsRead("com.apple.Siri", "SiriProfessionalEnabled")
			if err == nil && trim(out) == "1" {
				return Result{StatusFail, "Siri is enabled"}
			}
			return Result{StatusPass, "Siri is disabled"}
		},
	))
}
