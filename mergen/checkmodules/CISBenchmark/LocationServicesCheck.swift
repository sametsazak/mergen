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
            name: "Location services enabled",
            description: "Location Services is essential for various applications on your system to function properly. This check ensures that Location Services is enabled on your system.",
            category: "CIS Benchmark",
            remediation: "To enable Location Services, go to System Settings > Security & Privacy > Privacy and check the option.",
            severity: "Low",
            documentation: "This code checks the status of the com.apple.locationd launchctl service. If the locationd service is running, it means that Location Services is enabled; if not, it means that Location Services is disabled.",
            mitigation: "Enabling Location Services allows applications to provide location-based features and services.",
            docID: 50, cisID: "2.6.1.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.locationd"]

        task.standardOutput = Pipe()
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "Location Services is enabled."
                checkstatus = "Green"
            } else {
                status = "Location Services is disabled."
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
