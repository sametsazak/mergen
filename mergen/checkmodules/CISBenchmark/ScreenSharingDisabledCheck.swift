//
//  ScreenSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class ScreenSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Screen Sharing Is Disabled",
            description: "This check ensures that your Screen Sharing feature is disabled to prevent unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "To disable Screen Sharing, go to System Preferences > Sharing and uncheck the 'Screen Sharing' option.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/share-the-screen-of-another-mac-mh14066/mac",
            mitigation: "Disabling Screen Sharing reduces the risk of unauthorized access to your computer's files and resources by minimizing the ways an attacker can connect to your system.",
            docID: 18
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.screensharing"]

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = " Screen Sharing is Disabled"
                checkstatus = "Green"
            } else {
                status = " Screen Sharing is Enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Screen Sharing status"
            self.error = e
        }
    }
}
