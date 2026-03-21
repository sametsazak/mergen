//
//  RemoteLoginDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

//This implementation uses the launchctl command to check if the ssh process is running, which indicates that remote login is enabled.

class RemoteLoginDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Remote login (SSH) disabled",
            description: "Remote Login allows users to log in to your computer remotely via SSH. This check ensures that Remote Login is disabled to protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Remote Login, go to 'System Settings', click on 'Sharing', and uncheck the 'Remote Login' option.",
            severity: "Medium",
            documentation: "For more information about Remote Login and how to disable it, visit: https://support.apple.com/guide/mac-help/use-remote-login-mchla2c3e666/mac",
            mitigation: "Disabling Remote Login reduces the attack surface and helps prevent unauthorized access to your computer. This minimizes the ways an attacker can connect to your system and helps protect your data from unauthorized access.",
            docID: 38, cisID: "2.3.3.4"
        )
    }

    override func check() {
        // Use launchctl to check if sshd is loaded — safe, no network connection attempted
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.openssh.sshd"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "Remote Login (SSH) is enabled."
                checkstatus = "Red"
            } else {
                status = "Remote Login (SSH) is disabled."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Remote Login status"
        }
    }
}
