//
//  DiagnosticDataCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class DiagnosticDataCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Sending Diagnostic and Usage Data to Apple Status",
            description: "Check if sending diagnostic and usage data to Apple is disabled",
            category: "Privacy",
            remediation: "Go to System Preferences > Security & Privacy > Privacy > Analytics & Improvements, and select 'Off' for 'Share Mac Analytics'",
            severity: "Low",
            documentation: "This code checks if your system is set to send diagnostic and usage data to Apple. While sharing this data helps Apple improve its products and services, it may also expose sensitive information about your usage patterns.",
            mitigation: "To protect your privacy and prevent potential information leakage, you can disable sending diagnostic and usage data to Apple. To do this, go to System Preferences > Security & Privacy > Privacy > Analytics & Improvements, and select 'Off' for 'Share Mac Analytics'.",
            checkstatus: "",
            docID: 24
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist", "AutoSubmit"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "0" {
                status = "Apple data share is disabled."
                checkstatus = "Green"
            } else {
                status = "Apple data share is enabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking diagnostic data status"
        }
    }
}

