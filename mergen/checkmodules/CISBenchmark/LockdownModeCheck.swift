//
//  LockdownModeCheck.swift
//  mergen
//
//  CIS 2.6.7 - Ensure Lockdown Mode Is Enabled (Advisory)

import Foundation

class LockdownModeCheck: Vulnerability {
    init() {
        super.init(
            name: "Lockdown Mode Status",
            description: "Lockdown Mode provides extreme protection for users at high risk of targeted cyberattacks (e.g. journalists, activists, government officials). It severely limits device functionality to reduce attack surface.",
            category: "CIS Benchmark",
            remediation: "Enable in System Settings > Privacy & Security > Lockdown Mode. Note: This significantly limits device functionality. Only recommended for high-risk individuals.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.7",
            mitigation: "Lockdown Mode reduces attack surface against sophisticated targeted attacks by disabling certain features and connection types.",
            checkstatus: "",
            docID: 132,
            cisID: "2.6.7",
            isManual: true
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.security.lockdown", "LockdownModeEnabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Lockdown Mode is enabled."
                checkstatus = "Green"
            } else if output == "0" {
                status = "Lockdown Mode is disabled. Advisory: only required for high-risk users."
                checkstatus = "Blue"
            } else {
                status = "Lockdown Mode is not configured. Advisory check — enable only if user is high-risk."
                checkstatus = "Blue"
            }
        } catch {
            status = "Lockdown Mode status not determinable. Advisory: enable for high-risk individuals only."
            checkstatus = "Blue"
        }
    }
}
