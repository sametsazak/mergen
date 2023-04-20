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
            name: "Check HTTP Server Status",
            description: "This check ensures that the HTTP server is not running on your system, which helps protect against potential security vulnerabilities.",
            category: "Security",
            remediation: "To disable the built-in Apache server or configure it securely, follow the instructions in the provided documentation link.",
            severity: "Medium",
            documentation: "For more information on disabling or configuring the built-in Apache server, visit: https://support.apple.com/en-us/HT210060",
            mitigation: "Disabling or securely configuring the built-in Apache server helps protect your system from security vulnerabilities associated with running an HTTP server.",
            docID: 28
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/apachectl")
        task.arguments = ["-t"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased().contains("syntax ok") {
                status = "Apache Server is running."
                checkstatus = "Red"
            } else {
                status = "Apache Server is not Running."
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
