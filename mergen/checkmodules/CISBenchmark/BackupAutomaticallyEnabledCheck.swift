//
//  BackupAutomaticallyEnabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class BackupAutomaticallyCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Backup Automatically is Enabled If Time Machine Is Enabled",
            description: "Time Machine is a backup utility that helps to protect your data. This check ensures that if Time Machine is enabled, Backup Automatically is also enabled.",
            category: "CIS Benchmark",
            remediation: "To enable Backup Automatically, go to 'System Preferences', click on 'Time Machine', and check the 'Backup Automatically' option.",
            severity: "Medium",
            documentation: "For more information about Time Machine and Backup Automatically, visit: https://support.apple.com/guide/mac-help/what-is-time-machine-mh15139/mac",
            mitigation: "Enabling Backup Automatically helps to ensure that your system is regularly backed up, which helps prevent data loss and aids in data recovery if needed.",
            docID: 45
        )
    }

    override func check() {
        let fileManager = FileManager.default
        let filePath = "/Library/Preferences/com.apple.TimeMachine.plist"

        if fileManager.fileExists(atPath: filePath) {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
            task.arguments = ["read", filePath, "AutoBackup"]

            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            do {
                try task.run()
                task.waitUntilExit()

                if task.terminationStatus == 0 {
                    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                    let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)

                    if let autoBackup = outputString, autoBackup == "1" {
                        status = "Backup Automatically is Enabled"
                        checkstatus = "Green"
                    } else {
                        status = "Backup Automatically is Disabled"
                        checkstatus = "Red"
                    }
                } else {
                    status = "Error checking Time Machine status"
                    checkstatus = "Yellow"
                    self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
                }
            } catch let e {
                print("Error checking \(name): \(e)")
                checkstatus = "Yellow"
                status = "Error checking Time Machine status"
                self.error = e
            }
        } else {
            status = "Time Machine is Disabled"
            checkstatus = "Red"
        }
    }
}
