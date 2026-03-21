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
            name: "Time Machine enabled",
            description: "Check if Time Machine is enabled and has completed a backup",
            category: "CIS Benchmark",
            remediation: "Enable Time Machine in System Settings and run a backup",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/what-is-time-machine-mh15139/mac",
            mitigation: "Enabling Time Machine and running regular backups helps to ensure that your system is regularly backed up to prevent data loss.",
            docID: 46,
            cisID: "2.3.4.1"
        )
    }
    
    override func check() {
        // Check whether Time Machine has a configured destination (enabled),
        // not whether a backup is currently running.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/tmutil")
        task.arguments = ["destinationinfo"]
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.contains("Name") || output.contains("Kind") {
                status = "Time Machine is enabled and has a backup destination configured."
                checkstatus = "Green"
            } else {
                status = "Time Machine has no backup destination configured."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Time Machine status"
            self.error = e
        }
    }
}

