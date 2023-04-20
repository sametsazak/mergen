//
//  SIPCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SIPStatusCheck: Vulnerability {
    init() {
        super.init(
            name: "Check System Integrity Protection (SIP) Status",
            description: "This check verifies if System Integrity Protection (SIP) is enabled on your computer. SIP helps protect your computer from unauthorized changes and enhances security.",
            category: "Security",
            remediation: "To enable SIP, restart your computer in Recovery Mode and run `csrutil enable` in Terminal.",
            severity: "High",
            documentation: "For more information about SIP and how to enable it, visit: https://support.apple.com/en-us/HT204899",
            mitigation: "System Integrity Protection is a crucial security feature and should remain enabled to protect your system from unauthorized changes.",
            docID: 20
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        task.arguments = ["status"]
        
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            if output.lowercased().contains("enabled.") {
                status = "SIP is enabled."
                checkstatus = "Green"
            } else {
                status = "SIP is not enabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
        }
    }
}
