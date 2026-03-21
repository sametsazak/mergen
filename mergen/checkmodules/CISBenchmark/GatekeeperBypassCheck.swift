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
            name: "Gatekeeper enabled",
            description: "Verify that Gatekeeper is enabled to protect your Mac from potentially harmful software",
            category: "CIS Benchmark",
            remediation: "Enable Gatekeeper either by running 'sudo spctl --master-enable' in Terminal or by going to System Settings -> Security & Privacy -> General, and selecting 'App Store and identified developers' under 'Allow apps downloaded from'",
            severity: "High",
            documentation: "https://support.apple.com/en-us/HT202491",
            mitigation: "Gatekeeper helps protect your Mac by ensuring only trusted software is installed. If Gatekeeper is disabled, you are at a higher risk of installing malicious software. Keep Gatekeeper enabled to maintain a secure environment.",
            checkstatus: "",
            docID: 19, cisID: "2.6.5"
        )
    }
    
    override func check() {
        // spctl --status writes to stderr, not stdout, so we must capture stderr.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        task.arguments = ["--status"]

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        task.standardOutput = stdoutPipe
        task.standardError = stderrPipe

        do {
            try task.run()
            task.waitUntilExit()

            let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let combined = (stdout + stderr).lowercased()

            if combined.contains("assessments enabled") {
                status = "Gatekeeper is enabled."
                checkstatus = "Green"
            } else if combined.contains("assessments disabled") {
                status = "Gatekeeper is disabled."
                checkstatus = "Red"
            } else {
                status = "Could not determine Gatekeeper status."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            self.checkstatus = "Yellow"
            status = "Error checking Gatekeeper status"
        }
    }
}
