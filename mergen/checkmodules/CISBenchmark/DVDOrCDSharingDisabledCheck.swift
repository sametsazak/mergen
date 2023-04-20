//
//  DVDOrCDSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class DVDOrCDSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check DVD or CD Sharing Is Disabled",
            description: "This check ensures that your DVD or CD Sharing feature is disabled to prevent unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "To disable DVD or CD Sharing, go to System Preferences > Sharing and uncheck the 'DVD or CD Sharing' option.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/share-files-between-mac-computers-using-cd-or-dvd-sharing-mh15149/mac",
            mitigation: "Disabling DVD or CD Sharing reduces the risk of unauthorized access to your computer's files and resources by minimizing the ways an attacker can connect to your system.",
            docID: 17
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.ODSAgent"]

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "DVD or CD Sharing is Disabled"
                checkstatus = "Green"
            } else {
                status = "DVD or CD Sharing is Enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking DVD or CD Sharing status"
            self.error = e
        }
    }
}

