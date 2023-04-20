//
//  FirewallCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class FirewallCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Firewall Status",
            description: "The firewall helps protect your device from unauthorized access. This check verifies if the firewall is enabled and configured correctly.",
            category: "CIS Benchmark",
            remediation: "To enable and configure the firewall, go to System Preferences -> Security & Privacy -> Firewall, click 'Turn On Firewall', and 'Firewall Options...' to block incoming connections.",
            severity: "High",
            documentation: "For more information on configuring your firewall, visit: https://support.apple.com/en-us/HT201642",
            mitigation: "Enabling and configuring the firewall helps prevent unauthorized access to your device and increases overall security. A properly configured firewall can block incoming connections and minimize the risk of unauthorized access.",
            checkstatus: "",
            docID: 5
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"]
        
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            if output == "0" {
                status = "Firewall is not enabled."
                checkstatus = "Red"
            } else {
                let task2 = Process()
                task2.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                task2.arguments = ["defaults", "read", "/Library/Preferences/com.apple.alf", "allowsignedenabled"]
                
                let outputPipe2 = Pipe()
                task2.standardOutput = outputPipe2
                
                try task2.run()
                task2.waitUntilExit()
                
                let outputData2 = outputPipe2.fileHandleForReading.readDataToEndOfFile()
                let output2 = String(data: outputData2, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                
                if output2 == "1" {
                    status = "Firewall is enabled."
                    checkstatus = "Green"
                } else {
                    status = "Firewall is not enabled."
                    checkstatus = "Red"
                }
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
        }
    }
}

