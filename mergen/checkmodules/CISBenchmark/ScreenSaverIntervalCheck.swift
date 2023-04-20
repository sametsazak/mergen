//
//  ScreenSaverIntervalCheck.swift
//  mergen
//
//  Created by Samet Sazak
//


import Foundation

class ScreenSaverInactivityCheck: Vulnerability {

    init() {
        super.init(
            name: "Check an Inactivity Interval of 20 Minutes or Less for the Screen Saver Is Enabled",
            description: "This checks if the computer screen saver activates within 20 minutes of inactivity. A shorter inactivity period helps protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "Set the screen saver inactivity interval to 20 minutes or less.",
            severity: "Low",
            documentation: "A longer inactivity interval increases the risk of unauthorized access to a user's system and potentially sensitive data. This code checks if the screen saver activates within 20 minutes of inactivity.",
            mitigation: "Set the screen saver inactivity interval to 20 minutes or less to minimize the risk of unauthorized access.",
            docID: 57
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/defaults"
        task.arguments = ["read", "com.apple.screensaver", "idleTime"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if let value = Int(output.trimmingCharacters(in: .whitespacesAndNewlines)) {
                    if value <= 1200 {
                        status = "An inactivity interval of 20 minutes or less for the screen saver is enabled"
                        checkstatus = "Green"
                    } else {
                        status = "An inactivity interval of more than 20 minutes for the screen saver is enabled"
                        checkstatus = "Red"
                    }
                } else {
                    status = "Error parsing defaults output"
                    checkstatus = "Yellow"
                }
            } else {
                status = "Error parsing defaults output"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking screen saver inactivity interval"
            self.error = e
        }
    }
}

