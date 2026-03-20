//
//  ScreenSaverCornersCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class ScreenSaverCornersCheck: Vulnerability {
    init() {
        super.init(
            name: "Screen saver corners configured",
            description: "This check ensures that Screen Saver Corners are set to a secure option, preventing the screen saver from being easily deactivated and reducing potential security risks.",
            category: "CIS Benchmark",
            remediation: "To set Screen Saver Corners to a secure option, go to System Settings > Desktop & Screen Saver > Screen Saver > Hot Corners and select secure options for each corner.",
            severity: "Low",
            documentation: "Setting secure options for Screen Saver Corners helps prevent unauthorized access to your computer when the screen saver is active.",
            mitigation: "Configuring Screen Saver Corners with secure options ensures that the screen saver can only be deactivated using a secure method, enhancing the security of your system.",
            docID: 54, cisID: "2.7.1"
        )
    }

    override func check() {
        // CIS: no hot corner should be set to value 6 ("Disable Screen Saver")
        // Each corner key is read separately; defaults read only accepts one key at a time.
        let cornerKeys = ["wvous-tl-corner", "wvous-tr-corner", "wvous-bl-corner", "wvous-br-corner"]
        var cornerValues: [String] = []

        for key in cornerKeys {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
            task.arguments = ["read", "com.apple.dock", key]
            let pipe = Pipe()
            task.standardOutput = pipe
            task.standardError = Pipe()
            do {
                try task.run()
                task.waitUntilExit()
                let val = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                cornerValues.append(val)
            } catch {
                cornerValues.append("")
            }
        }

        // Value 6 = "Disable Screen Saver" — insecure per CIS
        if cornerValues.contains("6") {
            status = "A hot corner is set to 'Disable Screen Saver', which bypasses the lock screen."
            checkstatus = "Red"
        } else {
            status = "No hot corner is configured to disable the screen saver."
            checkstatus = "Green"
        }
    }
}

