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
            name: "Firewall stealth mode enabled",
            description: "Firewall Stealth Mode makes your computer less visible on public networks by ignoring incoming requests. This check verifies if Firewall Stealth Mode is enabled.",
            category: "CIS Benchmark",
            remediation: "To enable Firewall Stealth Mode, go to 'System Settings', click on 'Security & Privacy', select the 'Firewall' tab, click the lock to make changes, then click 'Firewall Options' and check 'Enable stealth mode'.",
            severity: "Medium",
            documentation: "For more information about Firewall Stealth Mode and how to enable it, visit: https://support.apple.com/guide/mac-help/use-stealth-mode-to-secure-your-mac-mh17131/mac",
            mitigation: "Enabling Firewall Stealth Mode helps prevent unauthorized access to your computer by making it less visible on public networks. It is recommended to enable Stealth Mode, especially when connected to untrusted networks.",
            checkstatus: "",
            docID: 12, cisID: "2.2.2"
        )
    }

    override func check() {
        // com.apple.alf plist was removed in macOS 26 Tahoe.
        // socketfilterfw is the only reliable API that works without sudo on all versions.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        task.arguments = ["--getstealthmode"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // Output is e.g. "Firewall stealth mode is on" or "Firewall stealth mode is off"
            if output.lowercased().contains("is on") {
                status = "Firewall Stealth Mode is enabled."
                checkstatus = "Green"
            } else {
                status = "Firewall Stealth Mode is disabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Firewall Stealth Mode status"
            self.error = e
        }
    }
}

