//
//  SudoTTYTicketsCheck.swift
//  mergen
//
//  CIS 5.5 - Ensure a Separate Timestamp Is Enabled for Each User/tty Combo

import Foundation

class SudoTTYTicketsCheck: Vulnerability {
    init() {
        super.init(
            name: "Sudo Uses Per-TTY Timestamps",
            description: "Using tty tickets ensures a user must enter the sudo password in each Terminal session separately, preventing background processes from inheriting elevated privileges.",
            category: "CIS Benchmark",
            remediation: "Add 'Defaults timestamp_type=tty' to a file in /etc/sudoers.d/ using: sudo visudo -f /etc/sudoers.d/cis_sudoconfig",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.5",
            mitigation: "Per-TTY sudo timestamps prevent privilege escalation by background processes spawned in different terminal sessions.",
            checkstatus: "",
            docID: 121,
            cisID: "5.5"
        )
    }

    override func check() {
        // On macOS Tahoe, sudo -V no longer shows full configuration.
        // Primary: check for the sudoers.d drop-in file written by our fix.
        // Fallback: parse sudo -V for older macOS / non-standard configs.
        if FileManager.default.fileExists(atPath: "/etc/sudoers.d/cis_tty") {
            status = "Sudo uses per-TTY timestamps."
            checkstatus = "Green"
            return
        }

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

            if output.contains("Type of authentication timestamp record: tty") {
                status = "Sudo uses per-TTY timestamps."
                checkstatus = "Green"
            } else {
                status = "Sudo does not use per-TTY timestamps — configure Defaults timestamp_type=tty."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking sudo TTY ticket configuration"
        }
    }
}
