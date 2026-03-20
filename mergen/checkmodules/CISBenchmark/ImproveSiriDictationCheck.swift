//
//  ImproveSiriDictationCheck.swift
//  mergen
//
//  CIS 2.6.3.2 - Ensure Improve Siri & Dictation Is Disabled

import Foundation

class ImproveSiriDictationCheck: Vulnerability {
    init() {
        super.init(
            name: "Improve Siri & Dictation Is Disabled",
            description: "This setting allows Apple to store and review audio of Siri and dictation interactions. Organizations should control what audio and interaction data is shared with Apple.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.assistant.support and set 'Siri Data Sharing Opt-In Status' to 2. Or go to System Settings > Privacy & Security > Analytics & Improvements and disable Improve Siri & Dictation.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.2",
            mitigation: "Disabling Siri data sharing prevents audio interactions from being sent to Apple for review.",
            checkstatus: "",
            docID: 106,
            cisID: "2.6.3.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support').objectForKey('Siri Data Sharing Opt-In Status').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "2" {
                status = "Improve Siri & Dictation is disabled (opt-out status 2)."
                checkstatus = "Green"
            } else if output.isEmpty || output == "undefined" || output == "null" {
                // Check user plist directly
                checkViaDefaults()
            } else {
                status = "Improve Siri & Dictation may be enabled (status: \(output))."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Siri & Dictation improvement setting"
        }
    }

    private func checkViaDefaults() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "com.apple.assistant.support", "Siri Data Sharing Opt-In Status"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "2" {
                status = "Improve Siri & Dictation is disabled."
                checkstatus = "Green"
            } else {
                status = "Improve Siri & Dictation state could not be determined."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Improve Siri & Dictation state could not be determined."
        }
    }
}
