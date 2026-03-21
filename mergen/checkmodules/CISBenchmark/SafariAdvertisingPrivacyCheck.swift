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
                checkViaDefaults()
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Safari advertising privacy protection"
        }
    }

    private func checkViaDefaults() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "com.apple.Safari", "WebKitPreferences.privateClickMeasurementEnabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Safari advertising privacy protection is enabled."
                checkstatus = "Green"
            } else {
                status = "Safari advertising privacy protection status unknown."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Could not verify Safari advertising privacy status."
        }
    }
}
