//
//  UniversalControlCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class UniversalControlCheck: Vulnerability {
    init() {
        super.init(
            name: "Universal control disabled",
            description: "This check ensures that Universal Control is disabled on your system, preventing unauthorized access to your computer and potentially sensitive data.",
            category: "CIS Benchmark",
            remediation: "To disable Universal Control, go to System Settings > Displays > Advanced and uncheck the 'Universal Control' option.",
            severity: "Low",
            documentation: "Disabling Universal Control helps protect your system by limiting the ways other devices can connect and interact with it.",
            mitigation: "By disabling Universal Control, you ensure that only authorized devices can connect to your system, reducing potential security risks.",
            docID: 55, cisID: "2.8.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["-currentHost", "read", "com.apple.universalcontrol", "Disable"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Universal Control is disabled."
                checkstatus = "Green"
            } else if task.terminationStatus != 0 {
                // Key absent = Universal Control is enabled (default)
                status = "Universal Control is enabled."
                checkstatus = "Red"
            } else {
                status = "Universal Control is enabled (Disable = 0)."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Universal Control status"
            self.error = e
        }
    }
}
