//
//  SafariFraudWarningCheck.swift
//  mergen
//
//  CIS 6.3.3 - Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled

import Foundation

class SafariFraudWarningCheck: Vulnerability {
    init() {
        super.init(
            name: "Safari Fraudulent Website Warning Is Enabled",
            description: "Safari uses the Google Safe Browsing API to warn users when visiting potentially fraudulent or malicious websites.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Safari and set WarnAboutFraudulentWebsites to true. Or enable in Safari > Settings > Security.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.3.3",
            mitigation: "Fraudulent website warnings alert users before they load potentially malicious content.",
            checkstatus: "",
            docID: 126,
            cisID: "6.3.3"
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

            if output.contains("WarnAboutFraudulentWebsites") {
                if output.contains("WarnAboutFraudulentWebsites = 1") ||
                   output.contains("WarnAboutFraudulentWebsites=1") {
                    status = "Safari fraudulent website warning is enabled (via profile)."
                    checkstatus = "Green"
                } else {
                    status = "Safari fraudulent website warning may be disabled (via profile)."
                    checkstatus = "Red"
                }
            } else {
                // Cannot verify from outside Safari's sandbox on macOS Tahoe.
                // Manual review required.
                status = "Cannot verify from outside Safari's sandbox. Check Safari > Settings > Privacy > enable 'Warn when visiting a fraudulent website'."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari fraud warning"
        }
    }
}
