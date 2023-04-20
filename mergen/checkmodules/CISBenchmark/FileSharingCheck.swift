//
//  FileSharingCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class FileSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check File Sharing Is Disabled",
            description: "File Sharing allows you to share files and resources with other users over a network. This check ensures that File Sharing is disabled to prevent unauthorized access to your files and resources.",
            category: "CIS Benchmark",
            remediation: "To disable File Sharing, go to 'System Preferences', click on 'Sharing', and uncheck the 'File Sharing' option.",
            severity: "Medium",
            documentation: "For more information about File Sharing and how to disable it, visit: https://support.apple.com/guide/mac-help/file-sharing-overview-mh17131/mac",
            mitigation: "Disabling File Sharing reduces the risk of unauthorized access to your computer's files and resources. This minimizes the ways an attacker can connect to your system and helps protect your data from unauthorized access.",
            docID: 36
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

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)

            if let output = outputString, output.contains("\"com.apple.smbd\" => enabled") {
                status = "File Sharing is Enabled"
                checkstatus = "Red"
            } else {
                status = "File Sharing is Disabled"
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking File Sharing status"
            self.error = e
        }
    }
}
