//
//  CheckTimeMachineEnabled.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class TimeMachineEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check that Time Machine is Enabled",
            description: "Check if Time Machine is enabled and has completed a backup",
            category: "CIS Benchmark",
            remediation: "Enable Time Machine in System Preferences and run a backup",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/what-is-time-machine-mh15139/mac",
            mitigation: "Enabling Time Machine and running regular backups helps to ensure that your system is regularly backed up to prevent data loss.",
            docID: 46
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/tmutil")
        task.arguments = ["status"]
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                if outputString?.contains("Running = 1;") == true {
                    status = "Time Machine is Enabled and has completed a backup"
                    checkstatus = "Green"
                } else {
                    status = "Time Machine is Enabled but has not completed a backup"
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
            print(e)
        }
    }
}

