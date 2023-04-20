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
            name: "Check Remote Login Is Disabled",
            description: "Remote Login allows users to log in to your computer remotely via SSH. This check ensures that Remote Login is disabled to protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Remote Login, go to 'System Preferences', click on 'Sharing', and uncheck the 'Remote Login' option.",
            severity: "Medium",
            documentation: "For more information about Remote Login and how to disable it, visit: https://support.apple.com/guide/mac-help/use-remote-login-mchla2c3e666/mac",
            mitigation: "Disabling Remote Login reduces the attack surface and helps prevent unauthorized access to your computer. This minimizes the ways an attacker can connect to your system and helps protect your data from unauthorized access.",
            docID: 38
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = ["-c", "ssh localhost 2>&1"]
        
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            if output.contains("Are you sure you want to continue connecting") || output.contains("Host key verification failed") {
                status = "SSH server is running."
                checkstatus = "Red"
            } else if output.contains("Connection refused") {
                status = "SSH is not enabled."
                checkstatus = "Green"
            } else {
                status = "Unable to determine SSH status."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
        }
    }
}
