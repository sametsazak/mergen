//
//  NfsServerCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class NfsServerCheck: Vulnerability {
    init() {
        super.init(
            name: "Check NFS Server Status",
            description: "This check ensures that the NFS server is not running on your system, which helps protect against potential security vulnerabilities.",
            category: "Security",
            remediation: "To disable the NFS server or configure it securely, follow the instructions in the provided documentation link.",
            severity: "Medium",
            documentation: "For more information on disabling or configuring the NFS server securely, visit: https://support.apple.com/en-us/HT210060",
            mitigation: "Disabling or securely configuring the NFS server helps protect your system from security vulnerabilities associated with running an NFS server.",
            docID: 29
        )
    }

    override func check() {
        let task1 = Process()
        task1.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task1.arguments = ["list"]

        let task2 = Process()
        task2.executableURL = URL(fileURLWithPath: "/usr/bin/grep")
        task2.arguments = ["-c", "com.apple.nfsd"]

        let pipeBetweenTasks = Pipe()
        let outputPipe = Pipe()

        task1.standardOutput = pipeBetweenTasks
        task2.standardInput = pipeBetweenTasks
        task2.standardOutput = outputPipe

        do {
            try task1.run()
            try task2.run()

            task1.waitUntilExit()
            task2.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "0" {
                status = "NFS Server is Disabled."
                checkstatus = "Green"
            } else {
                status = "NFS Server is Enabled."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking NFS server status"
        }
    }
}
