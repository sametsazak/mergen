//
//  SudoLoggingCheck.swift
//  mergen
//
//  CIS 5.11 - Ensure Logging Is Enabled for Sudo

import Foundation

class SudoLoggingCheck: Vulnerability {
    init() {
        super.init(
            name: "Sudo Logging Is Enabled",
            description: "Logging sudo commands captures all privileged activity in the unified log. In macOS 26, sudo logging is disabled by default and must be explicitly enabled.",
            category: "CIS Benchmark",
            remediation: "Add 'Defaults log_allowed' to a file in /etc/sudoers.d/ using: sudo visudo -f /etc/sudoers.d/cis_sudoconfig",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.11",
            mitigation: "Logging sudo commands provides an audit trail of privileged operations, which is essential for incident response.",
            checkstatus: "",
            docID: 125,
            cisID: "5.11"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        task.arguments = ["-V"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if output.contains("Log when a command is allowed by sudoers") {
                status = "Sudo logging is enabled."
                checkstatus = "Green"
            } else {
                status = "Sudo logging is not enabled — add 'Defaults log_allowed' to sudoers configuration."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking sudo logging configuration"
        }
    }
}
