//
//  ShareWithAppDevelopersCheck.swift
//  mergen
//
//  CIS 2.6.3.4 - Ensure 'Share with app developers' Is Disabled

import Foundation

class ShareWithAppDevelopersCheck: Vulnerability {
    init() {
        super.init(
            name: "Share with App Developers Is Disabled",
            description: "This setting allows Apple to share crash and usage data with app developers. Organizations should control what diagnostic data is shared with third parties.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowDiagnosticSubmission to false.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.4",
            mitigation: "Disabling app developer data sharing prevents crash and usage information from being forwarded to third-party developers.",
            checkstatus: "",
            docID: 108,
            cisID: "2.6.3.4"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowDiagnosticSubmission').js"]

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
                status = "Share with App Developers is disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Share with App Developers is enabled."
                checkstatus = "Red"
            } else {
                status = "Share with App Developers state unknown (may require MDM profile)."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Share with App Developers setting"
        }
    }
}
