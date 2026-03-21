//
//  TerminalSecureKeyboardCheck.swift
//  mergen
//
//  CIS 6.4.1 - Ensure Secure Keyboard Entry Terminal.app Is Enabled

import Foundation

class TerminalSecureKeyboardCheck: Vulnerability {
    init() {
        super.init(
            name: "Terminal Secure Keyboard Entry Is Enabled",
            description: "Secure Keyboard Entry in Terminal prevents other applications or network sniffers from detecting keystrokes typed in Terminal sessions. This protects passwords and commands entered in the terminal.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Terminal and set SecureKeyboardEntry to true. Or enable in Terminal > Settings > Profiles > Keyboard > Use Secure Keyboard Entry.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.4.1",
            mitigation: "Secure keyboard entry minimizes the risk of key loggers capturing terminal input, protecting sensitive commands and passwords.",
            checkstatus: "",
            docID: 130,
            cisID: "6.4.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal').objectForKey('SecureKeyboardEntry').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "true" {
                status = "Terminal Secure Keyboard Entry is enabled."
                checkstatus = "Green"
            } else if output == "false" {
                status = "Terminal Secure Keyboard Entry is disabled."
                checkstatus = "Red"
            } else {
                // Fall back to user defaults
                checkViaDefaults()
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Terminal Secure Keyboard Entry"
        }
    }

    private func checkViaDefaults() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "com.apple.Terminal", "SecureKeyboardEntry"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Terminal Secure Keyboard Entry is enabled."
                checkstatus = "Green"
            } else if output == "0" {
                status = "Terminal Secure Keyboard Entry is disabled."
                checkstatus = "Red"
            } else {
                status = "Terminal Secure Keyboard Entry state unknown."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Could not verify Terminal Secure Keyboard Entry status."
        }
    }
}
