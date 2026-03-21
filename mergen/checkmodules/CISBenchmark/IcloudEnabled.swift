//
//  IcloudEnabled.swift
//  mergen
//
//  Created by Samet Sazak
//
//  CIS 2.1.1.3 - Ensure iCloud Drive Document and Desktop Sync Is Disabled

import Foundation

class iCloudDriveCheck: Vulnerability {
    init() {
        super.init(
            name: "iCloud Drive Document and Desktop Sync Is Disabled",
            description: "iCloud Drive can sync Desktop and Documents folders to iCloud. For security-conscious environments, this data should remain local.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Apple Account > iCloud > iCloud Drive and disable 'Sync this Mac'. Alternatively run: defaults write com.apple.finder FXICloudDriveDesktop -bool false && defaults write com.apple.finder FXICloudDriveDocuments -bool false",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.1.1.3",
            mitigation: "Disabling iCloud Drive Document and Desktop sync keeps potentially sensitive files from being uploaded to cloud storage automatically.",
            checkstatus: "",
            docID: 3,
            cisID: "2.1.1.3"
        )
    }

    override func check() {
        // CIS 2.1.1.3 requires BOTH Desktop AND Documents sync to be disabled
        var desktopEnabled = false
        var documentsEnabled = false

        for (key, flag) in [("FXICloudDriveDesktop", { desktopEnabled = true }),
                             ("FXICloudDriveDocuments", { documentsEnabled = true })] {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
            task.arguments = ["read", "com.apple.finder", key]
            let pipe = Pipe()
            task.standardOutput = pipe
            task.standardError = Pipe()
            do {
                try task.run()
                task.waitUntilExit()
                let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if output == "1" { flag() }
            } catch {}
        }

        if desktopEnabled || documentsEnabled {
            var which: [String] = []
            if desktopEnabled { which.append("Desktop") }
            if documentsEnabled { which.append("Documents") }
            status = "iCloud Drive sync is enabled for: \(which.joined(separator: ", "))."
            checkstatus = "Red"
        } else {
            status = "iCloud Drive Desktop and Documents sync is disabled."
            checkstatus = "Green"
        }
    }
}
