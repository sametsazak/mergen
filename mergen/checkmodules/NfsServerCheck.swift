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
            name: "NFS server disabled",
            description: "This check ensures that the NFS server is not running on your system, which helps protect against potential security vulnerabilities.",
            category: "CIS Benchmark",
            remediation: "To disable the NFS server or configure it securely, follow the instructions in the provided documentation link.",
            severity: "Medium",
            documentation: "For more information on disabling or configuring the NFS server securely, visit: https://support.apple.com/en-us/HT210060",
            mitigation: "Disabling or securely configuring the NFS server helps protect your system from security vulnerabilities associated with running an NFS server.",
            docID: 29, cisID: "4.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.nfsd"]

        task.standardOutput = Pipe()
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "NFS Server is enabled."
                checkstatus = "Red"
            } else {
                status = "NFS Server is disabled."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking NFS server status"
        }
    }
}
