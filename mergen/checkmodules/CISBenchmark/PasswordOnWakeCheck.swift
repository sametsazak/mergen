//
//  PasswordOnWakeCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation


class PasswordOnWakeCheck: Vulnerability {

    init() {
        super.init(
            name: "Check a Password is Required to Wake the Computer from Sleep or Screen Saver",
            description: "Checks whether a password is required to wake the computer from sleep or screen saver",
            category: "CIS Benchmark",
            remediation: "Enable a password requirement to wake the computer from sleep or screen saver",
            severity: "Low",
            documentation: "This code checks whether a password is required to wake the computer from sleep or screen saver. If not enabled, it can allow unauthorized access to a user's system and potentially sensitive data.",
            mitigation: "Enable a password requirement to wake the computer from sleep or screen saver to ensure that only authorized users can access the system.",
            docID: 58
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/defaults"
        task.arguments = ["read", "com.apple.screensaver", "askForPassword"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                    status = "A password is required to wake the computer from sleep or screen saver"
                    checkstatus = "Green"
                } else {
                    status = "A password is NOT required to wake the computer from sleep or screen saver"
                    checkstatus = "Red"
                }
            } else {
                status = "Error parsing defaults output"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking password requirement on wake status"
            self.error = e
        }
    }
}
