//
//  RemoteAppleEventsCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

//This implementation first checks if the com.apple.RemoteAppleEvents.plist file exists using FileManager.fileExists(atPath:) method. If the file exists, it runs the defaults read command as before. If the file does not exist, it assumes that Remote Apple Events is disabled and sets the status to "Remote Apple Events is Disabled" and check status to "Green".
//Since I can't use sudo, this script is using the method shared here: https://www.stigviewer.com/stig/apple_os_x_10.12/2018-01-04/finding/V-76115
//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

class RemoteAppleEventsDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Remote Apple Events Is Disabled",
            description: "Remote Apple Events allows other users to send AppleScript events to your computer. This check ensures that Remote Apple Events is disabled to protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Remote Apple Events, go to 'System Preferences', click on 'Sharing', and uncheck the 'Remote Apple Events' option.",
            severity: "Medium",
            documentation: "For more information about Remote Apple Events and how to disable it, visit: https://support.apple.com/guide/mac-help/use-remote-apple-events-mchlp1628/mac",
            mitigation: "Disabling Remote Apple Events minimizes the risk of unauthorized access to your computer. This reduces the ways an attacker can remotely control your system and helps protect your data from unauthorized access.",
            docID: 40
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["print-disabled", "system"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)

                if let outputString = outputString, outputString.contains("\"com.apple.AEServer\" => disabled") {
                    status = "Remote Apple Events is Disabled"
                    checkstatus = "Green"
                } else {
                    status = "Remote Apple Events is Enabled"
                    checkstatus = "Red"
                }
            } else {
                status = "Error checking Remote Apple Events status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Remote Apple Events status"
            self.error = e
            print(e)
        }
    }
}
