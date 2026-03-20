//
//  SSVEnabledCheck.swift
//  mergen
//
//  CIS 5.1.4 - Ensure Signed System Volume (SSV) Is Enabled

import Foundation

class SSVEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Signed System Volume (SSV) Is Enabled",
            description: "Signed System Volume is a security feature that cryptographically seals the system volume. macOS will not boot if system files have been tampered with.",
            category: "CIS Benchmark",
            remediation: "If SSV is disabled, assume the OS is compromised. Back up your files and do a clean install. SSV is enabled by default and should never be disabled on a production system.",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.1.4",
            mitigation: "SSV ensures system files have not been tampered with, providing boot-time integrity verification.",
            checkstatus: "",
            docID: 117,
            cisID: "5.1.4"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        task.arguments = ["authenticated-root", "status"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = (String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "") +
                         (String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")

            if output.lowercased().contains("enabled") {
                status = "Signed System Volume is enabled."
                checkstatus = "Green"
            } else if output.lowercased().contains("disabled") {
                status = "Signed System Volume is DISABLED — system may be compromised."
                checkstatus = "Red"
            } else {
                status = "SSV status could not be determined."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Signed System Volume status"
        }
    }
}
