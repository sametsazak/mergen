//
//  CheckAuditDisEnabled.swift
//  mergen
//
//  Created by Samet Sazak
//


import Foundation

// This module checks if the com.apple.auditd service is running, which indicates security auditing is enabled.
// A check status of "Green" means security auditing is enabled; "Red" means it is not; "Yellow" indicates an error.

class SecurityAuditingCheck: Vulnerability {

    init() {
        super.init(
            name: "Security auditing enabled",
            description: "This checks if security auditing is enabled on your computer. Security auditing helps detect unauthorized access and protect sensitive data.",
            category: "CIS Benchmark",
            remediation: "Enable security auditing.",
            severity: "Low",
            documentation: "Security auditing helps detect unauthorized access to a user's system and sensitive data. This code checks if the com.apple.auditd service is running, which indicates security auditing is enabled.",
            mitigation: "Enable security auditing to ensure security events are logged and monitored.",
            docID: 59, cisID: "3.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.auditd"]

        let pipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = pipe
        task.standardError = errPipe

        do {
            try task.run()
            task.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let errOutput = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let combined = output + errOutput

            if combined.contains("com.apple.auditd") && !combined.contains("Could not find") {
                status = "Security auditing (BSM/auditd) is enabled."
                checkstatus = "Green"
            } else {
                // BSM/auditd was removed from macOS 26 Tahoe. Apple replaced it with
                // the Unified Log (log stream/log show). This check is no longer applicable
                // on Tahoe and newer systems.
                status = "BSM audit daemon not found. On macOS 26 Tahoe+, BSM/auditd was removed and replaced by Unified Logging."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking security auditing status."
            self.error = e
        }
    }
}
