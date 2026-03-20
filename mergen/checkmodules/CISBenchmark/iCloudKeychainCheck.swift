//
//  iCloudKeychainCheck.swift
//  mergen
//
//  CIS 2.1.1.1 - Ensure iCloud Keychain Is Disabled (Manual)

import Foundation

class iCloudKeychainCheck: Vulnerability {
    init() {
        super.init(
            name: "iCloud Keychain Is Disabled",
            description: "iCloud Keychain syncs passwords and sensitive credentials across Apple devices. Organizations should disable this to prevent credentials from leaving managed devices.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowCloudKeychainSync to false. Or go to System Settings > Apple ID > iCloud and disable Passwords & Keychain.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.1.1.1",
            mitigation: "Disabling iCloud Keychain prevents credentials from being synced to personal devices or non-managed Apple ID accounts.",
            checkstatus: "",
            docID: 131,
            cisID: "2.1.1.1",
            isManual: true
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudKeychainSync').js"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "false" {
                status = "iCloud Keychain sync is disabled via MDM profile."
                checkstatus = "Green"
            } else if output == "true" {
                status = "iCloud Keychain sync is enabled via MDM profile."
                checkstatus = "Red"
            } else {
                status = "Manual review required: Check System Settings > Apple ID > iCloud > Passwords & Keychain."
                checkstatus = "Blue"
            }
        } catch {
            status = "Manual review required: Check System Settings > Apple ID > iCloud > Passwords & Keychain."
            checkstatus = "Blue"
        }
    }
}
