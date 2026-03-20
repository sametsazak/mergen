//
//  SudoTimeoutCheck.swift
//  mergen
//
//  CIS 5.4 - Ensure the Sudo Timeout Period Is Set to Zero

import Foundation

class SudoTimeoutCheck: Vulnerability {
    init() {
        super.init(
            name: "Sudo Timeout Period Is Zero",
            description: "By default, sudo caches credentials for a period of time after use. Setting the timeout to zero requires the user to enter their password every time sudo is used, preventing privilege escalation by background processes.",
            category: "CIS Benchmark",
            remediation: "Add 'Defaults timestamp_timeout=0' to a file in /etc/sudoers.d/ using: sudo visudo -f /etc/sudoers.d/cis_sudoconfig",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.4",
            mitigation: "A zero sudo timeout prevents a window during which elevated privileges can be exploited by malicious processes.",
            checkstatus: "",
            docID: 120,
            cisID: "5.4"
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

            if output.contains("Authentication timestamp timeout: 0.0 minutes") {
                status = "Sudo timeout is set to zero — password required every time."
                checkstatus = "Green"
            } else {
                status = "Sudo timeout is not zero — credentials may be cached after use."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking sudo timeout configuration"
        }
    }
}
