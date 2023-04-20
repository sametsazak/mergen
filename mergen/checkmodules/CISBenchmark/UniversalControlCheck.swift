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
            name: "Check Universal Control is Disabled",
            description: "This check ensures that Universal Control is disabled on your system, preventing unauthorized access to your computer and potentially sensitive data.",
            category: "CIS Benchmark",
            remediation: "To disable Universal Control, go to System Preferences > Displays > Advanced and uncheck the 'Universal Control' option.",
            severity: "Low",
            documentation: "Disabling Universal Control helps protect your system by limiting the ways other devices can connect and interact with it.",
            mitigation: "By disabling Universal Control, you ensure that only authorized devices can connect to your system, reducing potential security risks.",
            docID: 55
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/defaults"
        task.arguments = ["-currentHost", "read", "com.apple.universalcontrol", "Disable"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.contains("does not exist") {
                    status = "Universal Control is disabled"
                    checkstatus = "Green"
                } else if output.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                    status = "Universal Control is disabled"
                    checkstatus = "Green"
                } else {
                    status = "Unknown Universal Control status"
                    checkstatus = "Yellow"
                }
            } else {
                status = "Error parsing Universal Control status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Universal Control status"
            self.error = e
        }
    }
}
