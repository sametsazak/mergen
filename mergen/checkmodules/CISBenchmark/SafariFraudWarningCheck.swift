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
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion < 26 {
            checkViaDefaults()
            return
        }

        // On macOS Tahoe and newer, Safari preferences are sandboxed and
        // cannot be read from an external process via `defaults`.
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
                // Cannot verify from outside Safari's sandbox on Tahoe+ when
                // the setting is not enforced via MDM. Manual review required.
                status = "Cannot verify from outside Safari's sandbox. Check Safari > Settings > Security > enable 'Warn when visiting a fraudulent website'."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari fraud warning"
        }
    }

    private func checkViaDefaults() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.Safari", "WarnAboutFraudulentWebsites"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Safari fraudulent website warning is enabled."
                checkstatus = "Green"
            } else if output == "0" {
                status = "Safari fraudulent website warning is disabled."
                checkstatus = "Red"
            } else {
                status = "Safari fraudulent website warning state unknown (default is enabled)."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Could not verify Safari fraud warning status."
        }
    }
}
