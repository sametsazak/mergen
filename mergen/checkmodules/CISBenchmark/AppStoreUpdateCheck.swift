//
//  AppStoreUpdateCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class AppStoreUpdatesCheck: Vulnerability {
    init() {
        super.init(
            name: "Check 'Install Application Updates from the App Store' Is Enabled",
            description: "Check if 'Install app updates from the App Store' is enabled in the App Store preferences",
            category: "CIS Benchmark",
            remediation: "Enable 'Install app updates from the App Store' in the App Store preferences",
            severity: "Medium",
            documentation: "https://support.apple.com/en-us/HT202180",
            mitigation: "Enabling automatic installation of app updates from the App Store helps ensure that security patches and software updates are installed in a timely manner.",
            docID: 9
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Install app updates from the App Store' is enabled"
                checkstatus = "Green"
            } else {
                status = "Install app updates from the App Store' is Not enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking App Store update status"
            self.error = e
        }
    }
}

