//
//  SafariCrossSiteTrackingCheck.swift
//  mergen
//
//  CIS 6.3.4 - Ensure Prevent Cross-site Tracking in Safari Is Enabled

import Foundation

class SafariCrossSiteTrackingCheck: Vulnerability {
    init() {
        super.init(
            name: "Safari Cross-Site Tracking Prevention Is Enabled",
            description: "Cross-site tracking allows data brokers to follow users across the internet. Safari's Intelligent Tracking Prevention should be enabled to protect user privacy.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Safari, set BlockStoragePolicy to 2, WebKitPreferences.storageBlockingPolicy to 1, and WebKitStorageBlockingPolicy to 1.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.3.4",
            mitigation: "Blocking cross-site tracking prevents data brokers from building user profiles across websites.",
            checkstatus: "",
            docID: 127,
            cisID: "6.3.4"
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

            if output.contains("BlockStoragePolicy") {
                let hasCorrectValue = output.contains("BlockStoragePolicy = 2") ||
                                     output.contains("BlockStoragePolicy=2")
                if hasCorrectValue {
                    status = "Safari cross-site tracking prevention is enabled (via profile)."
                    checkstatus = "Green"
                } else {
                    status = "Safari cross-site tracking prevention may not be fully configured."
                    checkstatus = "Red"
                }
            } else {
                // Cannot verify from outside Safari's sandbox on macOS Tahoe.
                // Manual review required.
                status = "Cannot verify from outside Safari's sandbox. Check Safari > Settings > Privacy > enable 'Prevent cross-site tracking'."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari cross-site tracking prevention"
        }
    }
}
