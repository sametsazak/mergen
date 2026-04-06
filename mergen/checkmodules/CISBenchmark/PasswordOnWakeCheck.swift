//
//  PasswordOnWakeCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation


class PasswordOnWakeCheck: Vulnerability {

    init() {
        super.init(
            name: "Password required on wake",
            description: "Checks whether a password is required to wake the computer from sleep or screen saver",
            category: "CIS Benchmark",
            remediation: "Enable a password requirement to wake the computer from sleep or screen saver",
            severity: "High",
            documentation: "This code checks whether a password is required to wake the computer from sleep or screen saver. If not enabled, it can allow unauthorized access to a user's system and potentially sensitive data.",
            mitigation: "Enable a password requirement to wake the computer from sleep or screen saver to ensure that only authorized users can access the system.",
            docID: 58, cisID: "2.11.2"
        )
    }

    override func check() {
        // On macOS 26 Tahoe, com.apple.screensaver keys may only exist in the
        // -currentHost domain. Try that first, then fall back to the user domain.
        let value = readAskForPassword(currentHost: true) ?? readAskForPassword(currentHost: false)

        switch value {
        case "1":
            status = "A password is required to wake the computer from sleep or screen saver."
            checkstatus = "Green"
        case "0":
            status = "A password is NOT required to wake the computer from sleep or screen saver."
            checkstatus = "Red"
        default:
            // Key absent means the setting was never explicitly configured — treat as not required.
            status = "A password is NOT required to wake the computer from sleep or screen saver."
            checkstatus = "Red"
        }
    }

    private func readAskForPassword(currentHost: Bool) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = currentHost
            ? ["-currentHost", "read", "com.apple.screensaver", "askForPassword"]
            : ["read", "com.apple.screensaver", "askForPassword"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return nil }
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return nil
        }
    }
}
