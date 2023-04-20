//
//  AutomaticSoftwareUpdateCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class AutomaticSoftwareUpdateCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Auto Update Is Enabled",
            description: "Checks if the 'Download new updates when available' option is enabled in the App Store preferences.",
            category: "CIS Benchmark",
            remediation: """
                Enable the 'Download new updates when available' option in the App Store preferences:

                1. Open 'System Preferences' on your Mac.
                2. Click on 'Software Update'.
                3. Check the box next to 'Automatically keep my Mac up to date'.
                4. Click the 'Advanced...' button.
                5. Make sure the 'Download new updates when available' option is checked.
            """,
            severity: "Medium",
            documentation: "https://support.apple.com/en-us/HT202180",
            mitigation: "Enabling automatic download of new updates ensures that your device receives important security patches and software updates in a timely manner.",
            checkstatus: "",
            docID: 8
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.commerce", "AutoUpdate"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Download New Updates When Available Is Enabled"
                checkstatus = "Green"
            } else {
                status = "Download New Updates When Available Is Not Enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking automatic software update status"
            self.error = e
        }
    }
}

