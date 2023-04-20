//
//  TimeWithinLimitsCheck.swift
//  mergen
//
//  Created by Samet Sazak

import Foundation

class TimeWithinLimitsCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Time Is Set Within Appropriate Limits",
            description: "This check verifies that your computer's system time is set within acceptable limits. Accurate system time is essential for the proper functioning of various applications and security features.",
            category: "CIS Benchmark",
            remediation: "To set the system time correctly, go to System Preferences > Date & Time, and make sure the 'Set date and time automatically' option is enabled. If necessary, manually adjust the date and time to match the current time.",
            severity: "High",
            documentation: "https://support.apple.com/guide/mac-help/set-the-date-and-time-mh35851/mac",
            mitigation: "Maintaining accurate system time is crucial for the proper operation of your computer and its applications. It also helps prevent potential security issues related to incorrect timekeeping, such as expired certificates or time-sensitive authentication mechanisms.",
            docID: 16
        )
    }

    override func check() {
        let maxTimeDelta = 300 // 5 minutes
        let now = Date()
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/date")
        task.arguments = ["+%s"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if let timestamp = Double(output) {
                let timeDelta = abs(now.timeIntervalSince1970 - timestamp)
                if timeDelta <= Double(maxTimeDelta) {
                    status = "The system time within the appropriate limits"
                    checkstatus = "Green"
                } else {
                    status = "The system time is not within the appropriate limits"
                    checkstatus = "Red"
                }
            } else {
                status = "The system time is not within the appropriate limits"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking system time"
            self.error = e
        }
    }
}

