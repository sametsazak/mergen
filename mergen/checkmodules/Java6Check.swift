//
//  Java6Check.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class Java6Check: Vulnerability {
    init() {
        super.init(
            name: "Check Java 6 Default Runtime Status",
            description: "Check if Java 6 is the default Java runtime. Java 6 is an outdated version and may expose your system to security risks.",
            category: "Security",
            remediation: "Install a newer version of Java and set it as the default runtime. Follow the instructions at https://www.java.com/en/download/help/download_options.xml to download and install the latest version of Java.",
            severity: "High",
            documentation: "https://www.java.com/en/download/help/download_options.xml",
            mitigation: "Using the latest version of Java helps protect your system against security vulnerabilities and ensures compatibility with the latest software.",
            checkstatus: "",
            docID: 25
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/java")
        task.arguments = ["-version"]

        let outputPipe = Pipe()
        task.standardError = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased().contains("java 1.6") {
                status = "Update Java Version."
                checkstatus = "Red"
            } else {
                status = "Java is up-to-date."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Java 6 status"
        }
    }
}
