//
//  GuestHomeFolderCheck.swift
//  mergen
//
//  CIS 5.9 - Ensure the Guest Home Folder Does Not Exist

import Foundation

class GuestHomeFolderCheck: Vulnerability {
    init() {
        super.init(
            name: "Guest Home Folder Does Not Exist",
            description: "After disabling the Guest account, the legacy /Users/Guest folder may remain. This folder is unneeded and could be used inappropriately or cause automated audits to fail.",
            category: "CIS Benchmark",
            remediation: "Run: sudo rm -R /Users/Guest (only after verifying the Guest account is disabled and this is a legacy folder).",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.9",
            mitigation: "Removing the unused Guest home folder reduces the attack surface and prevents its misuse.",
            checkstatus: "",
            docID: 123,
            cisID: "5.9"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ls")
        task.arguments = ["/Users/"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let folders = output.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }

            if folders.contains("Guest") {
                status = "Guest home folder exists at /Users/Guest."
                checkstatus = "Red"
            } else {
                status = "Guest home folder does not exist."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking for Guest home folder"
        }
    }
}
