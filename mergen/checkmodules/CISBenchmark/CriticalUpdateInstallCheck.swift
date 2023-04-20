//
//  CriticalUpdateInstallCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Since macOS Big Sur, the option to delay software updates has been removed from the system preferences. Therefore, it is not possible to check for a deferment period in newer macOS versions. This module checks for CriticalUpdateInstall check.
//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class CriticalUpdateInstallCheck: Vulnerability {
    init() {
        super.init(
            name: "Check 'Install system data files and security updates' Is Enabled",
            description: "Check if 'Install system data files and security updates' is enabled in the Software Update preferences",
            category: "CIS Benchmark",
            remediation: "Enable 'Install system data files and security updates' in the Software Update preferences",
            severity: "Medium",
            documentation: "https://support.apple.com/en-us/HT202180",
            mitigation: "Enabling the installation of system data files and security updates helps ensure that critical updates are installed in a timely manner.",
            docID: 12
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "'Install system data files and security updates' is enabled"
                checkstatus = "Green"
            } else {
                status = "'Install system data files and security updates' is not enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking critical update install status"
            self.error = e
        }
    }
}
