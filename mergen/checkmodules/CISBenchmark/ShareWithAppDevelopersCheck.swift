//
//  ShareWithAppDevelopersCheck.swift
//  mergen
//
//  CIS 2.6.3.4 - Ensure 'Share with app developers' Is Disabled

import Foundation

class ShareWithAppDevelopersCheck: Vulnerability {
    // Authoritative, world-readable plist the system writes when the user
    // toggles "Share with app developers" in System Settings.
    private static let diagnosticsPlistPath =
        "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
    private static let thirdPartyKey = "ThirdPartyDataSubmit"

    init() {
        super.init(
            name: "Share with App Developers Is Disabled",
            description: "This setting allows Apple to share crash and usage data with app developers. Organizations should control what diagnostic data is shared with third parties.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowDiagnosticSubmission to false.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.3.4",
            mitigation: "Disabling app developer data sharing prevents crash and usage information from being forwarded to third-party developers.",
            checkstatus: "",
            docID: 108,
            cisID: "2.6.3.4"
        )
    }

    override func check() {
        // 1) Prefer an MDM-forced value if one is present (higher priority).
        if let mdmValue = readMDMValue() {
            if mdmValue {
                status = "Share with App Developers is enabled (forced by MDM profile)."
                checkstatus = "Red"
            } else {
                status = "Share with App Developers is disabled (enforced by MDM profile)."
                checkstatus = "Green"
            }
            return
        }

        // 2) Otherwise read the world-readable authoritative plist.
        let path = ShareWithAppDevelopersCheck.diagnosticsPlistPath

        if !FileManager.default.fileExists(atPath: path) {
            // Fresh user: file isn't written until Analytics & Improvements
            // has been visited, which is equivalent to "never submitted".
            status = "Share with App Developers is disabled (no diagnostics history plist present)."
            checkstatus = "Green"
            return
        }

        guard let dict = NSDictionary(contentsOfFile: path) else {
            status = "Share with App Developers state could not be determined (plist unreadable)."
            checkstatus = "Yellow"
            return
        }

        // Key absent or 0 -> disabled (Green). 1 -> enabled (Red).
        if let raw = dict[ShareWithAppDevelopersCheck.thirdPartyKey] as? NSNumber {
            if raw.intValue == 1 {
                status = "Share with App Developers is enabled."
                checkstatus = "Red"
            } else {
                status = "Share with App Developers is disabled."
                checkstatus = "Green"
            }
        } else {
            status = "Share with App Developers is disabled (ThirdPartyDataSubmit key absent)."
            checkstatus = "Green"
        }
    }

    /// Check whether an MDM configuration profile is forcing
    /// allowDiagnosticSubmission for com.apple.applicationaccess. Returns
    /// nil when no profile enforces it.
    ///
    /// Note: the MDM key is inverted semantically
    /// (allowDiagnosticSubmission == false means sharing is disabled), so
    /// we normalize it to "is sharing enabled?".
    private func readMDMValue() -> Bool? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowDiagnosticSubmission').js"]

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
        // allowDiagnosticSubmission true  -> sharing allowed  -> enabled
        case "true", "1":  return true
        // allowDiagnosticSubmission false -> sharing blocked  -> disabled
        case "false", "0": return false
        default:           return nil
        }
    }
}
