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
            name: "Check Security Auditing Is Enabled",
            description: "This checks if security auditing is enabled on your computer. Security auditing helps detect unauthorized access and protect sensitive data.",
            category: "CIS Benchmark",
            remediation: "Enable security auditing.",
            severity: "Low",
            documentation: "Security auditing helps detect unauthorized access to a user's system and sensitive data. This code checks if the com.apple.auditd service is running, which indicates security auditing is enabled.",
            mitigation: "Enable security auditing to ensure security events are logged and monitored.",
            docID: 59
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/bin/launchctl"
        task.arguments = ["list", "com.apple.auditd"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.contains("com.apple.auditd") {
                    status = "Security auditing is enabled."
                    checkstatus = "Green"
                } else if output.contains("Could not find service") {
                    status = "Security auditing is not enabled."
                    checkstatus = "Red"
                } else {
                    status = "Error: Unable to parse the launchctl output."
                    checkstatus = "Yellow"
                }
            } else {
                status = "Error: Unable to parse the launchctl output."
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
