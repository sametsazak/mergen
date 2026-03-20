//
//  SiriStatusCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SiriEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Siri disabled",
            description: "Check if Siri is enabled",
            category: "CIS Benchmark",
            remediation: "Disable Siri by going to System Settings > Siri and unchecking 'Enable Ask Siri'",
            severity: "Low",
            documentation: "This code checks if Siri, Apple's voice assistant, is enabled on your system. While Siri can be helpful, it can also potentially be exploited by unauthorized individuals to access sensitive information or perform actions without your consent.",
            mitigation: "To reduce the risk of unauthorized voice commands, you can disable Siri. To do this, go to System Settings > Siri and uncheck the 'Enable Ask Siri' option.",
            checkstatus: "",
            docID: 23, cisID: "2.5.2.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.Siri", "SiriProfessionalEnabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // Key absent or 0 means Siri is disabled
            if output == "1" {
                status = "Siri is Enabled"
                checkstatus = "Red"
            } else {
                status = "Siri is Disabled"
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Siri status"
        }
    }
}

