//
//  AuditFlagsCheck.swift
//  mergen
//
//  CIS 3.3 - Ensure Audit Flags Are Configured Correctly

import Foundation

class AuditFlagsCheck: Vulnerability {
    init() {
        super.init(
            name: "Audit Flags Are Configured Correctly",
            description: "The macOS audit system (BSM/auditd) should be configured to log authentication, authorization, and administrative events to support forensic investigation and incident response.",
            category: "CIS Benchmark",
            remediation: "Edit /etc/security/audit_control and ensure flags include: lo,aa,ad,fd,fm,-all. Run 'sudo audit -s' to reload audit configuration.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 3.3",
            mitigation: "Proper audit flags ensure that authentication events, failed access attempts, and administrative actions are logged for security monitoring.",
            checkstatus: "",
            docID: 134,
            cisID: "3.3",
            isManual: false
        )
    }

    override func check() {
        // /etc/security/audit_control was removed in macOS 26 Tahoe along with BSM/auditd.
        // Check if the file exists before trying to read it.
        guard FileManager.default.fileExists(atPath: "/etc/security/audit_control") else {
            status = "BSM audit_control not found. On macOS 26 Tahoe+, BSM/auditd was removed and replaced by Unified Logging."
            checkstatus = "Yellow"
            return
        }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/grep")
        task.arguments = ["^flags:", "/etc/security/audit_control"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // CIS requires: lo,aa,ad,fd,fm,-all
            let requiredFlags = ["lo", "aa", "ad", "fd", "fm"]
            let hasAllFlags = requiredFlags.allSatisfy { output.contains($0) }

            if hasAllFlags {
                status = "Audit flags include required events: \(output)"
                checkstatus = "Green"
            } else if output.isEmpty {
                status = "Audit flags not configured. Required: lo,aa,ad,fd,fm,-all"
                checkstatus = "Red"
            } else {
                status = "Audit flags may be incomplete: \(output). Required: lo,aa,ad,fd,fm,-all"
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Could not read audit configuration."
        }
    }
}
