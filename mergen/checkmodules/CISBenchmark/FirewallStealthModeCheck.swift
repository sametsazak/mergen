//
//  FirewallStealthModeCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class FirewallStealthModeCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Firewall Stealth Mode Is Enabled",
            description: "Firewall Stealth Mode makes your computer less visible on public networks by ignoring incoming requests. This check verifies if Firewall Stealth Mode is enabled.",
            category: "CIS Benchmark",
            remediation: "To enable Firewall Stealth Mode, go to 'System Preferences', click on 'Security & Privacy', select the 'Firewall' tab, click the lock to make changes, then click 'Firewall Options' and check 'Enable stealth mode'.",
            severity: "Medium",
            documentation: "For more information about Firewall Stealth Mode and how to enable it, visit: https://support.apple.com/guide/mac-help/use-stealth-mode-to-secure-your-mac-mh17131/mac",
            mitigation: "Enabling Firewall Stealth Mode helps prevent unauthorized access to your computer by making it less visible on public networks. It is recommended to enable Stealth Mode, especially when connected to untrusted networks.",
            checkstatus: "",
            docID: 12
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.alf", "stealthenabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Check if Firewall Stealth Mode is enabled"
                checkstatus = "Green"
            } else {
                checkstatus = "Red"
                status = "Check if Firewall Stealth Mode is enabled"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Firewall Stealth Mode status"
            self.error = e
        }
    }
}

