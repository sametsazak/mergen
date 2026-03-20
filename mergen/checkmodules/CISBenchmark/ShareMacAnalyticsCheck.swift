//
//  ShareMacAnalyticsCheck.swift
//  mergen
//
//  CIS 2.6.3.1 - Ensure Share Mac Analytics Is Disabled

import Foundation

class ShareMacAnalyticsCheck: Vulnerability {
    init() {
        super.init(
            name: "Share Mac Analytics Is Disabled",
            description: "Share Mac Analytics automatically sends diagnostic and usage data to Apple. Organizations should control what data is shared with vendors.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.SubmitDiagInfo and set AutoSubmit to false. Or go to System Settings > Privacy & Security > Analytics & Improvements and disable Share Mac Analytics.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.1",
            mitigation: "Disabling Mac Analytics prevents internal organizational data from being automatically forwarded to Apple.",
            checkstatus: "",
            docID: 105,
            cisID: "2.6.3.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo').objectForKey('AutoSubmit').js"]

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
                status = "Share Mac Analytics is disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Share Mac Analytics is enabled."
                checkstatus = "Red"
            } else {
                // Fall back to direct defaults read (user-level)
                checkViaDefaults()
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Share Mac Analytics"
        }
    }

    private func checkViaDefaults() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "com.apple.SubmitDiagInfo", "AutoSubmit"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "0" {
                status = "Share Mac Analytics is disabled."
                checkstatus = "Green"
            } else if output == "1" {
                status = "Share Mac Analytics is enabled."
                checkstatus = "Red"
            } else {
                status = "Share Mac Analytics state could not be determined."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Share Mac Analytics state could not be determined."
        }
    }
}
