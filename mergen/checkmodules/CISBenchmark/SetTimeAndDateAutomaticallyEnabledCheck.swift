//
//  SetTimeAndDateAutomaticallyEnabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SetTimeAndDateAutomaticallyEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check 'Set Time and Date Automatically' Is Enabled",
            description: "This check ensures that your computer automatically updates its date and time settings. This helps maintain accurate timekeeping and prevent potential security issues.",
            category: "CIS Benchmark",
            remediation: "To enable automatic date and time updates, go to System Preferences > Date & Time and check the box next to 'Set date and time automatically'.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/set-the-date-and-time-mh35851/mac",
            mitigation: "Keeping your computer's date and time accurate helps ensure proper functioning of the system and its applications. It also helps avoid potential security issues related to incorrect timekeeping.",
            docID: 15
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.timezone.auto.plist", "Active"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Set Time and Date Automatically is Enabled"
                checkstatus = "Green"
            } else {
                status = "Set Time and Date Automatically is Disabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Set Time and Date Automatically status"
            self.error = e
        }
    }
}

