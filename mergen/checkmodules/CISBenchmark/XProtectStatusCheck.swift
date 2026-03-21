//
//  XProtectStatusCheck.swift
//  mergen
//
//  CIS 5.10 - Ensure XProtect Is Running and Updated

import Foundation

class XProtectStatusCheck: Vulnerability {
    init() {
        super.init(
            name: "XProtect Is Running and Updated",
            description: "XProtect is Apple's native signature-based antivirus that blocks known malware. It should always be running with current signatures. XProtect can only be disabled if SIP is also disabled.",
            category: "CIS Benchmark",
            remediation: "Run: sudo launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist to re-enable XProtect if disabled.",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.10",
            mitigation: "XProtect provides baseline malware protection and should always be running with current signatures.",
            checkstatus: "",
            docID: 124,
            cisID: "5.10"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/xprotect")
        task.arguments = ["status"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let errorOutput = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let combined = output + errorOutput

            if combined.contains("enabled") && !combined.contains("disabled") {
                status = "XProtect is running."
                checkstatus = "Green"
            } else if combined.contains("disabled") {
                status = "XProtect is disabled — system may be compromised."
                checkstatus = "Red"
            } else {
                // Fall back to checking if xprotect binary exists (older approach)
                checkViaLaunchctl()
            }
        } catch {
            // xprotect command may not exist on older systems, try launchctl
            checkViaLaunchctl()
        }
    }

    private func checkViaLaunchctl() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", "com.apple.XProtect.daemon.scan"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                status = "XProtect service is running."
                checkstatus = "Green"
            } else {
                status = "XProtect service not found — system may be compromised or SIP disabled."
                checkstatus = "Yellow"
            }
        } catch {
            checkstatus = "Yellow"
            status = "Error checking XProtect status"
        }
    }
}
