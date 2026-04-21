//
//  LocationServicesMenuBarCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation


// This check reads the authoritative preference
// /Library/Preferences/com.apple.locationmenu.plist (key: ShowSystemServices).
// The value is an Integer: 1 means the Location Services indicator is shown
// (in the menu bar on older macOS, or in Control Center on macOS 26 Tahoe
// or later), 0 means it is hidden. Using this plist avoids false positives
// from probing com.apple.systemuiserver's menuExtras array, which no longer
// contains "Location.menu" on recent macOS versions even when the indicator
// is enabled.


class LocationServicesMenuBarCheck: Vulnerability {
    init() {
        super.init(
            name: "Location services shown in menu bar",
            description: "This check ensures that the Location Services indicator is visible (in the menu bar, or in Control Center on macOS 26 Tahoe or later), providing users with awareness when Location Services is enabled.",
            category: "CIS Benchmark",
            remediation: "To show the Location Services indicator, go to System Settings > Privacy & Security > Location Services > Details... and enable 'Show location icon in the menu bar when System Services request your location' (on macOS 26 Tahoe or later the indicator appears in Control Center).",
            severity: "Low",
            documentation: "Authoritative source is /Library/Preferences/com.apple.locationmenu.plist key ShowSystemServices (1 = enabled, 0 = disabled). On macOS 26 Tahoe or later the indicator was moved from the menu bar to Control Center but the preference key is unchanged.",
            mitigation: "Displaying the Location Services indicator ensures users are aware of when Location Services is enabled, reducing potential privacy risks.",
            docID: 51, cisID: "2.6.1.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.locationmenu.plist", "ShowSystemServices"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

                if output == "1" {
                    status = "Location Services indicator is enabled (menu bar, or Control Center on macOS 26 Tahoe or later)"
                    checkstatus = "Green"
                } else {
                    status = "Location Services indicator is disabled (menu bar, or Control Center on macOS 26 Tahoe or later)"
                    checkstatus = "Red"
                }
            } else {
                // `defaults read` exited non-zero — typically means the plist
                // or key is absent, which is treated as disabled.
                status = "Location Services indicator is disabled (menu bar, or Control Center on macOS 26 Tahoe or later)"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Location Services indicator status"
            self.error = e
        }
    }
}
