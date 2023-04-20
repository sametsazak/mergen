//
//  CheckMediaSharingDisabled.swift
//  mergen
//
//  Created by Samet Sazak
//

//This script uses the defaults command to read the value of the home-sharing-enabled key in the com.apple.amp.mediasharingd domain. If the value is 1, it means Media Sharing is enabled, and the status is set to "Media Sharing is Enabled" with a check status of "Red". If the value is 0, it means Media Sharing is disabled, and the status is set to "Media Sharing is Disabled" with a check status of "Green".

import Foundation

class MediaSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Media Sharing Is Disabled",
            description: "Media Sharing allows your computer to share media with other devices. This check ensures that Media Sharing is disabled to protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Media Sharing, go to 'System Preferences', click on 'Sharing', and uncheck the 'Media Sharing' option.",
            severity: "Medium",
            documentation: "For more information about Media Sharing and how to disable it, visit: https://support.apple.com/en-us/HT202190",
            mitigation: "Disabling Media Sharing reduces the attack surface and helps prevent unauthorized access to your computer. This minimizes the ways an attacker can connect to your system and helps protect your media files from unauthorized access.",
            docID: 43
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.amp.mediasharingd", "home-sharing-enabled"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                if outputString == "1" {
                    status = "Media Sharing is Enabled"
                    checkstatus = "Red"
                } else {
                    status = "Media Sharing is Disabled"
                    checkstatus = "Green"
                }
            } else {
                status = "Error checking Media Sharing status"
                checkstatus = "Yellow"
                self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Media Sharing status"
            self.error = e
            print(e)
        }
    }
}
