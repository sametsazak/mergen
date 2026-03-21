//
//  ImproveAssistiveVoiceCheck.swift
//  mergen
//
//  CIS 2.6.3.3 - Ensure Improve Assistive Voice Features Is Disabled

import Foundation

class ImproveAssistiveVoiceCheck: Vulnerability {
    init() {
        super.init(
            name: "Improve Assistive Voice Features Is Disabled",
            description: "This setting shares audio recordings and transcripts of Vocal Shortcuts and Voice Control interactions with Apple. These recordings may include PII or sensitive organizational information.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Accessibility and set AXSAudioDonationSiriImprovementEnabled to false.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.3",
            mitigation: "Disabling assistive voice improvement prevents sensitive audio from being shared with Apple.",
            checkstatus: "",
            docID: 107,
            cisID: "2.6.3.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Accessibility').objectForKey('AXSAudioDonationSiriImprovementEnabled').js"]

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
                status = "Improve Assistive Voice Features is disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Improve Assistive Voice Features is enabled."
                checkstatus = "Red"
            } else {
                status = "Improve Assistive Voice Features state unknown (may require MDM)."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Assistive Voice improvement setting"
        }
    }
}
