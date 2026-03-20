//
//  ApacheHTTPCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class HttpServerCheck: Vulnerability {
    init() {
        super.init(
            name: "Apache HTTP server disabled",
            description: "This check ensures that the HTTP server is not running on your system, which helps protect against potential security vulnerabilities.",
            category: "CIS Benchmark",
            remediation: "To disable the built-in Apache server or configure it securely, follow the instructions in the provided documentation link.",
            severity: "Medium",
            documentation: "For more information on disabling or configuring the built-in Apache server, visit: https://support.apple.com/en-us/HT210060",
            mitigation: "Disabling or securely configuring the built-in Apache server helps protect your system from security vulnerabilities associated with running an HTTP server.",
            docID: 28, cisID: "4.2"
        )
    }

    override func check() {
        // Check whether httpd is actually running via launchctl, not config syntax
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "org.apache.httpd"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "Apache HTTP server is running."
                checkstatus = "Red"
            } else {
                status = "Apache HTTP server is not running."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking HTTP server status"
        }
    }
}
