//
//  AdminPasswordForSystemPrefsCheck.swift
//  mergen
//
//  CIS 2.6.8 - Ensure an Administrator Password Is Required to Access System-Wide Preferences

import Foundation

class AdminPasswordForSystemPrefsCheck: Vulnerability {
    init() {
        super.init(
            name: "Admin Password Required for System-Wide Preferences",
            description: "System-wide preferences like Network, Startup Disk, and Time Machine should require an administrator password. This prevents users from making changes that affect the entire system.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Privacy & Security > Advanced and enable 'Require an administrator password to access system-wide settings'. Or use: security authorizationdb write system.preferences allow-root false",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.6.8",
            mitigation: "Requiring admin authentication for system preferences reduces the risk of unauthorized configuration changes.",
            checkstatus: "",
            docID: 109,
            cisID: "2.6.8"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["authorizationdb", "read", "system.preferences"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            // Check that shared is false AND group is admin
            let hasSharedFalse = output.contains("<key>shared</key>") &&
                output.contains("<false/>")
            let hasAdminGroup = output.contains("<string>admin</string>")

            if hasSharedFalse && hasAdminGroup {
                status = "Admin password is required for system-wide preferences."
                checkstatus = "Green"
            } else {
                status = "Admin password may not be required for system-wide preferences."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking system preferences authorization"
        }
    }
}
