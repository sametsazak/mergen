//
//  HomeFolderPermissionsCheck.swift
//  mergen
//
//  CIS 6.1.2 - Ensure No World Writable Files Exist in the System Folder (Manual)

import Foundation

class HomeFolderPermissionsCheck: Vulnerability {
    init() {
        super.init(
            name: "Home Folder Permissions Are Restrictive",
            description: "User home folders should not be readable by other users. Overly permissive home directory permissions expose sensitive files including SSH keys, shell history, and application data.",
            category: "CIS Benchmark",
            remediation: "Run: sudo chmod 700 /Users/<username> for each user account. Check with: ls -la /Users/ to verify permissions show drwx------ for each user directory.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 6.1.2",
            mitigation: "Restricting home folder permissions prevents other local users from browsing each other's files, reducing lateral movement risk.",
            checkstatus: "",
            docID: 133,
            cisID: "6.1.2",
            isManual: false
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/stat")
        task.arguments = ["-f", "%A", "/Users"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
        } catch {}

        // Check each user home folder
        let lsTask = Process()
        lsTask.executableURL = URL(fileURLWithPath: "/bin/ls")
        lsTask.arguments = ["-la", "/Users/"]

        let lsOutput = Pipe()
        lsTask.standardOutput = lsOutput
        lsTask.standardError = Pipe()

        do {
            try lsTask.run()
            lsTask.waitUntilExit()

            let output = String(data: lsOutput.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let lines = output.components(separatedBy: "\n")

            // Look for world-readable home dirs (permissions like drwxr-xr-x)
            let problematic = lines.filter { line in
                guard line.count > 10 else { return false }
                let perms = String(line.prefix(10))
                // Check if 'others' have read/execute bit (position 7, 8, 9)
                let othersRead = perms.count >= 8 && String(perms[perms.index(perms.startIndex, offsetBy: 7)]) == "r"
                let hasUserDir = line.contains("/Users/") == false &&
                                 !line.hasSuffix(".") &&
                                 !line.contains("Shared") &&
                                 perms.hasPrefix("d")
                return othersRead && hasUserDir
            }

            if problematic.isEmpty {
                status = "Home folder permissions appear restrictive."
                checkstatus = "Green"
            } else {
                status = "Some home folders may have world-readable permissions. Manual review recommended."
                checkstatus = "Yellow"
            }
        } catch {
            status = "Manual review required: Run 'ls -la /Users/' to check home folder permissions."
            checkstatus = "Blue"
        }
    }
}
