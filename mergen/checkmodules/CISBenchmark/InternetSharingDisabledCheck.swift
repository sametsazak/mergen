//
//  InternetSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

//This implementation checks for the existence of the file at /Library/Preferences/SystemConfiguration/com.apple.nat, and if it exists, it runs the defaults read command to check for the string "Enabled = 1;" in the output. If the file does not exist, it assumes that Internet Sharing is disabled and sets the status to "Internet Sharing is Disabled" and check status to "Green".

//Some people, when confronted with a problem, think "I know, I'll use regular expressions." Now they have two problems.
// I hate regex.


class InternetSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Internet Sharing Is Disabled",
            description: "Internet Sharing allows your computer to share its internet connection with other devices. This check ensures that Internet Sharing is disabled to protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Internet Sharing, go to 'System Preferences', click on 'Sharing', and uncheck the 'Internet Sharing' option.",
            severity: "Medium",
            documentation: "For more information about Internet Sharing and how to disable it, visit: https://support.apple.com/guide/mac-help/share-your-internet-connection-mchlp1540/mac",
            mitigation: "Disabling Internet Sharing reduces the attack surface and helps prevent unauthorized access to your computer. This minimizes the ways an attacker can connect to your system and helps protect your data from unauthorized access.",
            docID: 41
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/SystemConfiguration/com.apple.nat"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                if let outputString = String(data: outputData, encoding: .utf8) {
                    let lines = outputString.components(separatedBy: .newlines)
                    for (index, line) in lines.enumerated() {
                        if line.contains("NatPortMapDisabled") {
                            let enabledLine = lines[index - 1]
                            let enabledValue = enabledLine.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "Enabled = ", with: "").replacingOccurrences(of: ";", with: "")
                            
                            if enabledValue == "1" {
                                status = "Internet Sharing is Enabled"
                                checkstatus = "Red"
                            } else {
                                status = "Internet Sharing is Disabled"
                                checkstatus = "Green"
                            }
                            break
                        }
                    }
                } else {
                    status = "Error checking Internet Sharing status"
                    checkstatus = "Yellow"
                }
            } else {
                status = "Error checking Internet Sharing status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Internet Sharing status"
            self.error = e
            print(e)
        }
    }
}
