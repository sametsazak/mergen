//
//  PasswordHintsCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class PasswordHintsCheck: Vulnerability {
    init() {
        super.init(
            name: "Check 'Show Password Hints' Status",
            description: "This check verifies if the 'Show password hints' option is disabled on your system, which helps protect against unauthorized access to your computer.",
            category: "Security",
            remediation: "To disable 'Show password hints', go to System Preferences > Users & Groups > Login Options, and uncheck the 'Show password hints' option.",
            severity: "Medium",
            documentation: "For more information on disabling 'Show password hints', visit: https://support.apple.com/guide/mac-help/change-password-preferences-mchlp2818/mac",
            mitigation: "By disabling 'Show password hints', you reduce the risk of unauthorized access to your computer, enhancing its security.",
            docID: 30
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.loginwindow.plist", "RetriesUntilHint"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "0" {
                status = "Password Hint is Disabled"
                checkstatus = "Green"
            } else {
                status = "Password Hint is Enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking password hints status"
        }
    }
}

