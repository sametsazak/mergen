//
//  ScreenSaverIntervalCheck.swift
//  mergen
//
//  Created by Samet Sazak
//


import Foundation

class ScreenSaverInactivityCheck: Vulnerability {

    init() {
        super.init(
            name: "Screen saver activates within 20 minutes",
            description: "This checks if the computer screen saver activates within 20 minutes of inactivity. A shorter inactivity period helps protect your computer from unauthorized access.",
            category: "CIS Benchmark",
            remediation: "Set the screen saver inactivity interval to 20 minutes or less.",
            severity: "Low",
            documentation: "A longer inactivity interval increases the risk of unauthorized access to a user's system and potentially sensitive data. This code checks if the screen saver activates within 20 minutes of inactivity.",
            mitigation: "Set the screen saver inactivity interval to 20 minutes or less to minimize the risk of unauthorized access.",
            docID: 57, cisID: "2.11.1"
        )
    }

    override func check() {
        // On macOS 26 Tahoe, `defaults read com.apple.screensaver idleTime` may return
        // nothing for the user domain. Try -currentHost (hardware-specific prefs) first,
        // then fall back to the plain user domain.
        let idleTime = readIdleTime(currentHost: true) ?? readIdleTime(currentHost: false)

        guard let value = idleTime else {
            status = "Screen saver inactivity interval is not set (screen saver may be disabled)."
            checkstatus = "Red"
            return
        }

        if value == 0 {
            status = "Screen saver is disabled (idleTime = 0)."
            checkstatus = "Red"
        } else if value <= 1200 {
            status = "Screen saver activates after \(value / 60) minute(s) — within the 20-minute CIS limit."
            checkstatus = "Green"
        } else {
            status = "Screen saver activates after \(value / 60) minute(s), which exceeds the 20-minute CIS limit."
            checkstatus = "Red"
        }
    }

    private func readIdleTime(currentHost: Bool) -> Int? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = currentHost
            ? ["-currentHost", "read", "com.apple.screensaver", "idleTime"]
            : ["read", "com.apple.screensaver", "idleTime"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return nil }
            let raw = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return Int(raw)
        } catch {
            return nil
        }
    }
}

