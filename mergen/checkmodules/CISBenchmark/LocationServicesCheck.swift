//
//  LocationServicesCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class LocationServicesCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Location Services Is Enabled",
            description: "Location Services is essential for various applications on your system to function properly. This check ensures that Location Services is enabled on your system.",
            category: "Privacy",
            remediation: "To enable Location Services, go to System Preferences > Security & Privacy > Privacy and check the option.",
            severity: "Low",
            documentation: "This code checks the status of the com.apple.locationd launchctl service. If the locationd service is running, it means that Location Services is enabled; if not, it means that Location Services is disabled.",
            mitigation: "Enabling Location Services allows applications to provide location-based features and services.",
            docID: 50
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/bin/launchctl"
        task.arguments = ["list"]

        let grepTask = Process()
        grepTask.launchPath = "/usr/bin/grep"
        grepTask.arguments = ["-c", "com.apple.locationd"]

        let pipe = Pipe()
        let grepPipe = Pipe()
        task.standardOutput = pipe
        grepTask.standardInput = pipe
        grepTask.standardOutput = grepPipe

        do {
            try task.run()
            try grepTask.run()
            task.waitUntilExit()
            grepTask.waitUntilExit()

            let outputData = grepPipe.fileHandleForReading.readDataToEndOfFile()
            let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)

            if outputString == "1" {
                status = "Location Services is Enabled"
                checkstatus = "Green"
            } else {
                status = "Location Services is Disabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Location Services status"
            self.error = e
        }
    }
}
