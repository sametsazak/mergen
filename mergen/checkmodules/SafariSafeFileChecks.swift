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
            name: "Safari auto-open safe files disabled",
            description: "This check ensures that the automatic run of safe files in Safari is disabled, which helps prevent the execution of malicious code.",
            category: "CIS Benchmark",
            remediation: "Open Safari > Settings > General and uncheck Open safe files after downloading. On macOS Tahoe, Safari preferences are sandboxed and cannot be changed via command line.",
            severity: "Medium",
            documentation: "For more information on disabling the automatic run of safe files in Safari, visit: https://support.apple.com/guide/safari/preference-settings-for-security-ibrw1093/mac",
            mitigation: "Disabling the automatic run of safe files helps protect your system from the execution of malicious code that may be disguised as a safe file.",
            docID: 33, cisID: "6.3.1"
        )
    }

    override func check() {
            // On macOS Tahoe, Safari preferences are fully sandboxed.
            // External processes cannot read or write them via defaults.
            // Read the container plist directly; if the write was blocked by cfprefsd
            // the key will be absent, which means Safari is using its default (enabled).
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
            task.arguments = ["read", "com.apple.Safari", "AutoOpenSafeDownloads"]

            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = Pipe()

            do {
                try task.run()
                task.waitUntilExit()

                let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

                if output.lowercased() == "0" {
                    status = "Automatic run of safe files in Safari is disabled."
                    checkstatus = "Green"
                } else if task.terminationStatus != 0 || output.isEmpty {
                    // Key absent — cannot verify from outside Safari's sandbox.
                    // Manual review required: check Safari > Settings > General.
                    status = "Cannot verify from outside Safari's sandbox. Check Safari > Settings > General > uncheck 'Open safe files after downloading'."
                    checkstatus = "Yellow"
                } else {
                    status = "Safari auto-open safe files is enabled — change in Safari > Settings > General."
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
