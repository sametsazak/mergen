//
//  SafariAdvertisingPrivacyCheck.swift
//  mergen
//
//  CIS 6.3.6 - Ensure Advertising Privacy Protection in Safari Is Enabled

import Foundation

class SafariAdvertisingPrivacyCheck: Vulnerability {
    init() {
        super.init(
            name: "Safari Advertising Privacy Protection Is Enabled",
            description: "Safari's privacy-preserving ad measurement (Private Click Measurement) allows basic ad effectiveness measurement without revealing which ad was clicked or building user profiles.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.Safari and set WebKitPreferences.privateClickMeasurementEnabled to true.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.3.6",
            mitigation: "Enabling privacy-preserving ad measurement prevents advertisers from tracking users across sites while allowing basic analytics.",
            checkstatus: "",
            docID: 128,
            cisID: "6.3.6"
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

            if output.contains("privateClickMeasurementEnabled") {
                if output.contains("privateClickMeasurementEnabled = 1") ||
                   output.contains("privateClickMeasurementEnabled=1") {
                    status = "Safari advertising privacy protection is enabled (via profile)."
                    checkstatus = "Green"
                } else {
                    status = "Safari advertising privacy protection is not enabled (via profile)."
                    checkstatus = "Red"
                }
            } else {
                // Cannot verify from outside Safari's sandbox on macOS Tahoe.
                // Manual review required. The label for this setting has
                // varied across macOS versions — on Tahoe it appears as
                // 'Privacy Preserving Ad Measurement' under Advanced; older
                // macOS versions use 'Allow privacy-preserving measurement
                // of ad effectiveness' or similar wording.
                status = "Cannot verify from outside Safari's sandbox. Check Safari > Settings > Advanced > enable 'Privacy Preserving Ad Measurement' (older macOS: 'Allow privacy-preserving measurement of ad effectiveness')."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari advertising privacy protection"
        }
    }
}
