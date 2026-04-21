//
//  LocationServicesCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class LocationServicesCheck: Vulnerability {
    init() {
        super.init(
            name: "Location services enabled",
            description: "Location Services is essential for various applications on your system to function properly. This check ensures that Location Services is enabled on your system.",
            category: "CIS Benchmark",
            remediation: "To enable Location Services, go to System Settings > Security & Privacy > Privacy and check the option.",
            severity: "Low",
            documentation: "This check inspects the com.apple.locationd system LaunchDaemon. On macOS 26 Tahoe, `launchctl list` (no domain) no longer surfaces system daemons, so we probe `launchctl print system/com.apple.locationd` instead and look for `state = running`. A legacy `launchctl list | grep locationd` fallback keeps older macOS versions working.",
            mitigation: "Enabling Location Services allows applications to provide location-based features and services.",
            docID: 50, cisID: "2.6.1.1"
        )
    }

    override func check() {
        // Primary check: `launchctl print system/com.apple.locationd` works on
        // modern macOS (including 26 Tahoe) where `launchctl list` no longer
        // enumerates system LaunchDaemons from a user domain.
        let printTask = Process()
        printTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        printTask.arguments = ["print", "system/com.apple.locationd"]

        let printOutputPipe = Pipe()
        printTask.standardOutput = printOutputPipe
        printTask.standardError = Pipe()

        do {
            try printTask.run()
            printTask.waitUntilExit()

            if printTask.terminationStatus == 0 {
                let outputData = printOutputPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: outputData, encoding: .utf8) ?? ""
                if output.contains("state = running") {
                    status = "Location Services is enabled (locationd running)"
                    checkstatus = "Green"
                } else {
                    status = "Location Services is disabled"
                    checkstatus = "Red"
                }
                return
            }
            // Non-zero exit: fall through to legacy fallback below.
        } catch let e {
            // `launchctl print` itself failed to execute — try the legacy path.
            print("launchctl print failed for \(name), falling back: \(e)")
        }

        // Fallback for very old macOS where `launchctl print system/...` is
        // unavailable: the original `launchctl list com.apple.locationd`
        // probe. Exit code 0 means the daemon is loaded in the current domain.
        let legacyTask = Process()
        legacyTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        legacyTask.arguments = ["list", "com.apple.locationd"]
        legacyTask.standardOutput = Pipe()
        legacyTask.standardError = Pipe()

        do {
            try legacyTask.run()
            legacyTask.waitUntilExit()

            if legacyTask.terminationStatus == 0 {
                status = "Location Services is enabled."
                checkstatus = "Green"
            } else {
                status = "Location Services is disabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Location Services status"
            self.error = e
        }
    }
}
