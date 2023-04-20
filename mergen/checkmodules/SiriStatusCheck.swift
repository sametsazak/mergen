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
            name: "Check Siri Status",
            description: "Check if Siri is enabled",
            category: "Privacy",
            remediation: "Disable Siri by going to System Preferences > Siri and unchecking 'Enable Ask Siri'",
            severity: "Low",
            documentation: "This code checks if Siri, Apple's voice assistant, is enabled on your system. While Siri can be helpful, it can also potentially be exploited by unauthorized individuals to access sensitive information or perform actions without your consent.",
            mitigation: "To reduce the risk of unauthorized voice commands, you can disable Siri. To do this, go to System Preferences > Siri and uncheck the 'Enable Ask Siri' option.",
            checkstatus: "",
            docID: 23
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.Siri", "StatusMenuVisible"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Siri is Enabled"
                checkstatus = "Red"
            } else {
                status = "Siri is Disabled"
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
        }
    }
}

