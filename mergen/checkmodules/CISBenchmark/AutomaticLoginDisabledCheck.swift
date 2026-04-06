//
//  AutomaticLoginDisabledCheck.swift
//  mergen
//
//  CIS 2.13.3 - Ensure Automatic Login Is Disabled

import Foundation

class AutomaticLoginDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Automatic Login Is Disabled",
            description: "Automatic login allows a computer to bypass the login window and log in as a specific user. This exposes the system to anyone with physical access.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Lock Screen and disable 'Automatically log in as'. Or run: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
            severity: "Critical",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.13.3",
            mitigation: "Disabling automatic login ensures physical access to the machine does not grant immediate access to the user session.",
            checkstatus: "",
            docID: 115,
            cisID: "2.13.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]

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

            if output.isEmpty || errorOutput.contains("does not exist") {
                status = "Automatic login is disabled."
                checkstatus = "Green"
            } else {
                status = "Automatic login is enabled for user: \(output)."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking automatic login status"
        }
    }
}
