//
//  LoginScreenMessageCheck.swift
//  mergen
//
//  CIS 2.11.3 - Ensure a Custom Message for the Login Screen Is Enabled

import Foundation

class LoginScreenMessageCheck: Vulnerability {
    init() {
        super.init(
            name: "Custom Login Screen Message Is Set",
            description: "A login screen access warning informs users that the system is reserved for authorized use only. This may reduce casual attacker tendency and aids prosecution by establishing awareness of policies.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Lock Screen > Show message when locked and set your organization's message. Or run: sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText 'Your message here'",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.11.3",
            mitigation: "A login banner establishes that the system is for authorized use only, which may deter casual attackers.",
            checkstatus: "",
            docID: 113,
            cisID: "2.11.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "LoginwindowText"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let errorOutput = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if !output.isEmpty && !errorOutput.contains("does not exist") {
                status = "Login screen message is set."
                checkstatus = "Green"
            } else {
                status = "No custom login screen message is configured."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking login screen message"
        }
    }
}
