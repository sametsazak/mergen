//
//  SafariStatusBarCheck.swift
//  mergen
//
//  CIS 6.3.10 - Ensure Show Status Bar Is Enabled in Safari

import Foundation

class SafariStatusBarCheck: Vulnerability {
    init() {
        super.init(
            name: "Safari Status Bar Is Enabled",
            description: "The Safari Status Bar shows the full URL of hovered links, allowing users to verify where a link points before clicking. This helps identify phishing and obfuscated URLs.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Safari and set ShowOverlayStatusBar to true.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.3.10",
            mitigation: "Showing the status bar allows users to review full link URLs before navigating, reducing phishing risk.",
            checkstatus: "",
            docID: 129,
            cisID: "6.3.10"
        )
    }

    override func check() {
        // On macOS Tahoe, Safari preferences are fully sandboxed and cannot be
        // read from an external process via `defaults`. MDM-managed profiles
        // are still visible through system_profiler, so prefer that signal
        // when present; otherwise fall back to a manual-verification warning.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        task.arguments = ["SPConfigurationProfileDataType"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if output.contains("ShowOverlayStatusBar") {
                if output.contains("ShowOverlayStatusBar = 1") ||
                   output.contains("ShowOverlayStatusBar=1") {
                    status = "Safari status bar is enabled (via profile)."
                    checkstatus = "Green"
                } else {
                    status = "Safari status bar is not enabled (via profile)."
                    checkstatus = "Red"
                }
            } else {
                // Cannot verify from outside Safari's sandbox on macOS Tahoe.
                // Manual review required.
                status = "Cannot verify from outside Safari's sandbox. In Safari, open the View menu and choose 'Show Status Bar'."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari status bar"
        }
    }
}
