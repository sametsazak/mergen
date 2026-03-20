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
            name: "Guest access to shared folders disabled",
            description: "This check ensures that the 'Allow guests to connect to shared folders' option is disabled on your system, which helps protect against unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "To disable 'Allow guests to connect to shared folders', go to System Settings > Sharing, and uncheck the 'Allow guests to connect to shared folders' option.",
            severity: "Medium",
            documentation: "For more information on disabling 'Allow guests to connect to shared folders', visit: https://support.apple.com/guide/mac-help/share-mac-files-with-windows-users-mh14132/mac",
            mitigation: "By disabling 'Allow guests to connect to shared folders', you reduce the risk of unauthorized access to your computer's shared folders, enhancing its security.",
            docID: 31, cisID: "2.13.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.AppleFileServer", "guestAccess"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // defaults read returns "0" (disabled) or "1" (enabled)
            if output == "0" || task.terminationStatus != 0 {
                status = "Guest access to shared folders is disabled"
                checkstatus = "Green"
            } else {
                status = "Guest access to shared folders is enabled"
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

