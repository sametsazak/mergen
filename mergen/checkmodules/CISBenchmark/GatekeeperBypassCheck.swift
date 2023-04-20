//
//  GatekeeperBypassCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class GatekeeperBypassCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Gatekeeper Status",
            description: "Verify that Gatekeeper is enabled to protect your Mac from potentially harmful software",
            category: "CIS Benchmark",
            remediation: "Enable Gatekeeper either by running 'sudo spctl --master-enable' in Terminal or by going to System Preferences -> Security & Privacy -> General, and selecting 'App Store and identified developers' under 'Allow apps downloaded from'",
            severity: "High",
            documentation: "https://support.apple.com/en-us/HT202491",
            mitigation: "Gatekeeper helps protect your Mac by ensuring only trusted software is installed. If Gatekeeper is disabled, you are at a higher risk of installing malicious software. Keep Gatekeeper enabled to maintain a secure environment.",
            checkstatus: "",
            docID: 19
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["spctl", "--status"]
        
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            if output.lowercased().contains("assessments enabled") {
                status = "Gatekeeper is Enabled."
                checkstatus="Green"
            } else {
                status = "Gatekeeper is not enabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            self.checkstatus = "Yellow"
            status = "Error checking Gatekeeper Bypass"
        }
    }
}
