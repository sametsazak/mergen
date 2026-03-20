//
//  AMFIEnabledCheck.swift
//  mergen
//
//  CIS 5.1.3 - Ensure Apple Mobile File Integrity (AMFI) Is Enabled

import Foundation

class AMFIEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Apple Mobile File Integrity (AMFI) Is Enabled",
            description: "AMFI is the macOS kernel module that enforces code-signing and library validation. Disabling it allows unsigned code to run, significantly weakening system security.",
            category: "CIS Benchmark",
            remediation: "Run: sudo nvram boot-args='' to clear any boot arguments that disable AMFI. Note: AMFI cannot be disabled while SIP is enabled.",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.1.3",
            mitigation: "AMFI ensures that only properly signed code runs on the system, preventing execution of malicious or tampered applications.",
            checkstatus: "",
            docID: 116,
            cisID: "5.1.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/nvram")
        task.arguments = ["-p"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if output.contains("amfi_get_out_of_my_way=1") {
                status = "AMFI is disabled via boot argument amfi_get_out_of_my_way=1."
                checkstatus = "Red"
            } else {
                status = "AMFI is enabled (no disabling boot argument found)."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking AMFI status"
        }
    }
}
