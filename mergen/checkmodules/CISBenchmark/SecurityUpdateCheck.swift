//
//  SecurityUpdateCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class SecurityUpdatesCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Install Security Responses and System Files Is Enabled",
            description: "Check if 'Install system data files and security updates' is enabled in the App Store preferences",
            category: "Security",
            remediation: "Enable 'Install system data files and security updates' in the App Store preferences",
            severity: "Medium",
            documentation: "https://support.apple.com/en-us/HT202180",
            mitigation: "Enabling automatic installation of system data files and security updates helps ensure that security patches and software updates are installed in a timely manner.",
            checkstatus: "",
            docID: 10
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Install system data files and security updates' is enabled"
                checkstatus = "Green"
            } else {
                status = "Install system data files and security updates' is not enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking security update status"
            self.error = e
        }
    }
}

