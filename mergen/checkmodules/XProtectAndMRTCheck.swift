//
//  XProtectAndMRTCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class XProtectAndMRTCheck: Vulnerability {
    init() {
        super.init(
            name: "Check XProtect Status",
            description: "This check verifies if XProtect and MRT are enabled on your system, providing additional protection against malware and other security threats.",
            category: "Security",
            remediation: "To enable XProtect and MRT, go to System Preferences > Security & Privacy > General, and check the 'Automatically update built-in system data files' option.",
            severity: "High",
            documentation: "For more information about XProtect and MRT, visit: https://support.apple.com/en-us/HT202491",
            mitigation: "Enabling XProtect and MRT helps protect your system by detecting and removing known malware and addressing other security threats.",
            docID: 21
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
        task.arguments = ["-pl", "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"]
        
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            if output.lowercased().contains("com.apple.quarantine") {
                status = "Xprotect is enabled."
                checkstatus = "Green"
            } else {
                status = "Xprotect is not enabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
        }
    }
}

