//
//  TimeMachineVolumesEncryptedCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class TimeMachineVolumesEncryptedCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Time Machine Volumes Are Encrypted If Time Machine Is Enabled",
            description: "Check if Time Machine volumes are encrypted when Time Machine is enabled",
            category: "CIS Benchmark",
            remediation: "Enable encryption for Time Machine volumes",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/encrypt-time-machine-backup-disks-mh15141/mac",
            mitigation: "Encrypting Time Machine volumes helps protect your backup data from unauthorized access in case your backup disk is lost or stolen.",
            docID: 47
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.TimeMachine.plist"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            if task.terminationStatus == 0 {
                let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                
                if let searchString = outputString, searchString.contains("NotEncrypted") {
                    status = "Time Machine volumes are Not Encrypted"
                    checkstatus = "Red"
                } else {
                    status = "Time Machine volumes are Encrypted"
                    checkstatus = "Green"
                }
            } else {
                status = "Error checking Time Machine encryption status"
                checkstatus = "Yellow"
                self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Time Machine encryption status"
            self.error = e
        }
    }
}
