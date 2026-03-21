//
//  MailSummarizationCheck.swift
//  mergen
//
//  CIS 2.5.1.3 - Ensure Mail Summarization Is Disabled

import Foundation

class MailSummarizationCheck: Vulnerability {
    init() {
        super.init(
            name: "Apple Intelligence Mail Summarization Disabled",
            description: "Apple Intelligence Mail summarization condenses emails using AI. For environments with sensitive communications, this should be disabled to prevent mail content from being processed externally.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowMailSummary to false.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.5.1.3",
            mitigation: "Disabling mail summarization ensures email content is not processed by AI services outside your approved channels.",
            checkstatus: "",
            docID: 103,
            cisID: "2.5.1.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowMailSummary').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "false" {
                status = "Mail Summarization is disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Mail Summarization is enabled."
                checkstatus = "Red"
            } else {
                status = "No MDM profile found. Mail Summarization state unknown."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Apple Intelligence Mail Summarization"
        }
    }
}
