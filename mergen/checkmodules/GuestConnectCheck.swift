//
//  GuestConnectCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class GuestConnectCheck: Vulnerability {
    init() {
        super.init(
            name: "Check 'Allow guests to connect to shared folders' Status",
            description: "This check ensures that the 'Allow guests to connect to shared folders' option is disabled on your system, which helps protect against unauthorized access to your computer.",
            category: "Security",
            remediation: "To disable 'Allow guests to connect to shared folders', go to System Preferences > Sharing, and uncheck the 'Allow guests to connect to shared folders' option.",
            severity: "Medium",
            documentation: "For more information on disabling 'Allow guests to connect to shared folders', visit: https://support.apple.com/guide/mac-help/share-mac-files-with-windows-users-mh14132/mac",
            mitigation: "By disabling 'Allow guests to connect to shared folders', you reduce the risk of unauthorized access to your computer's shared folders, enhancing its security.",
            docID: 31
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.AppleFileServer", "guestAccess"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "no" {
                status = "Allow guests to connect to shared folders' is disabled"
                checkstatus = "Green"
            } else {
                status = "Allow guests to connect to shared folders' is enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking guest connect status"
        }
    }
}

