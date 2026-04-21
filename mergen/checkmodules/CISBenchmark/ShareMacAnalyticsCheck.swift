//
//  ShareMacAnalyticsCheck.swift
//  mergen
//
//  CIS 2.6.3.1 - Ensure Share Mac Analytics Is Disabled

import Foundation

class ShareMacAnalyticsCheck: Vulnerability {
    // Authoritative, world-readable plist the system writes when the user
    // toggles Share Mac Analytics in System Settings.
    private static let diagnosticsPlistPath =
        "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    private static let autoSubmitKey = "AutoSubmit"

    init() {
        super.init(
            name: "Share Mac Analytics Is Disabled",
            description: "Share Mac Analytics automatically sends diagnostic and usage data to Apple. Organizations should control what data is shared with vendors.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.SubmitDiagInfo and set AutoSubmit to false. Or go to System Settings > Privacy & Security > Analytics & Improvements and disable Share Mac Analytics.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.1",
            mitigation: "Disabling Mac Analytics prevents internal organizational data from being automatically forwarded to Apple.",
            checkstatus: "",
            docID: 105,
            cisID: "2.6.3.1"
        )
    }

    override func check() {
        // 1) Prefer an MDM-forced value if one is present (higher priority).
        if let mdmValue = readMDMValue() {
            if mdmValue {
                status = "Share Mac Analytics is enabled (forced by MDM profile)."
                checkstatus = "Red"
            } else {
                status = "Share Mac Analytics is disabled (enforced by MDM profile)."
                checkstatus = "Green"
            }
            return
        }

        // 2) Otherwise read the world-readable authoritative plist.
        let path = ShareMacAnalyticsCheck.diagnosticsPlistPath

        if !FileManager.default.fileExists(atPath: path) {
            // Fresh user: file isn't written until Analytics & Improvements
            // has been visited, which is equivalent to "never submitted".
            status = "Share Mac Analytics is disabled (no diagnostics history plist present)."
            checkstatus = "Green"
            return
        }

        guard let dict = NSDictionary(contentsOfFile: path) else {
            status = "Share Mac Analytics state could not be determined (plist unreadable)."
            checkstatus = "Yellow"
            return
        }

        // Key absent or 0 -> disabled (Green). 1 -> enabled (Red).
        if let raw = dict[ShareMacAnalyticsCheck.autoSubmitKey] as? NSNumber {
            if raw.intValue == 1 {
                status = "Share Mac Analytics is enabled."
                checkstatus = "Red"
            } else {
                status = "Share Mac Analytics is disabled."
                checkstatus = "Green"
            }
        } else {
            status = "Share Mac Analytics is disabled (AutoSubmit key absent)."
            checkstatus = "Green"
        }
    }

    /// Check whether an MDM configuration profile is forcing AutoSubmit for
    /// com.apple.SubmitDiagInfo. Returns nil when no profile enforces it.
    private func readMDMValue() -> Bool? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo').objectForKey('AutoSubmit').js"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return nil
        }

        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        switch output {
        case "true", "1":  return true
        case "false", "0": return false
        default:           return nil
        }
    }
}
