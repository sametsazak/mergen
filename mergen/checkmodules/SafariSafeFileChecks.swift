//
//  SafariSafeFileChecks.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SafariSafeFilesCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Automatic Run of Safe Files in Safari",
            description: "This check ensures that the automatic run of safe files in Safari is disabled, which helps prevent the execution of malicious code.",
            category: "Security",
            remediation: "To disable the automatic run of safe files in Safari, go to Safari > Preferences > General, and uncheck the 'Open “safe” files after downloading' option.",
            severity: "Medium",
            documentation: "For more information on disabling the automatic run of safe files in Safari, visit: https://support.apple.com/guide/safari/preference-settings-for-security-ibrw1093/mac",
            mitigation: "Disabling the automatic run of safe files helps protect your system from the execution of malicious code that may be disguised as a safe file.",
            docID: 33
        )
    }

    override func check() {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
            task.arguments = ["read", "com.apple.Safari", "AutoOpenSafeDownloads"]

            let outputPipe = Pipe()
            task.standardOutput = outputPipe

            do {
                try task.run()
                task.waitUntilExit()

                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

                if output.lowercased() == "0" {
                    status = "Automatic run of safe files in Safari is disabled"
                    checkstatus = "Green"
                } else {
                    status = "automatic run of safe files in Safari is enabled"
                    checkstatus = "Red"
                }
            } catch let e {
                print("Error checking \(name): \(e)")
                checkstatus = "Yellow"
                status = "Error checking Safari safe files status"
                self.error = e
            }
        }
    }
