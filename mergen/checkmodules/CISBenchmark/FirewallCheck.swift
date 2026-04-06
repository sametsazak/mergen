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
            name: "Firewall enabled",
            description: "The firewall helps protect your device from unauthorized access. This check verifies if the firewall is enabled and configured correctly.",
            category: "CIS Benchmark",
            remediation: "To enable and configure the firewall, go to System Settings... -> Network -> Firewall, enable the firewall, and configure it using the 'Options...' button.",
            severity: "Critical",
            documentation: "For more information on configuring your firewall, visit: https://support.apple.com/en-us/HT201642",
            mitigation: "Enabling and configuring the firewall helps prevent unauthorized access to your device and increases overall security. A properly configured firewall can block incoming connections and minimize the risk of unauthorized access.",
            checkstatus: "",
            docID: 5, cisID: "2.2.1"
        )
    }
    
    override func check() {
        // com.apple.alf plist was removed in macOS 26 Tahoe.
        // socketfilterfw is the only reliable API that works without sudo on all versions.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        task.arguments = ["--getglobalstate"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // Output is e.g. "Firewall is enabled. (State = 1)" or "Firewall is disabled. (State = 0)"
            if output.lowercased().contains("enabled") {
                status = "Firewall is enabled."
                checkstatus = "Green"
            } else {
                status = "Firewall is disabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Firewall status"
        }
    }
}

