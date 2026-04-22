//
//  BluetoothSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

// This check reads com.apple.Bluetooth PrefKeyServicesEnabled via
// `defaults -currentHost read`. The CIS-compliant state is disabled:
//   • stdout "0" or a missing preference key  → Green (disabled)
//   • stdout "1"                              → Red   (enabled)
//   • any other stdout / decode failure       → Yellow (unexpected value)
//   • `defaults` non-zero exit without "does not exist" in stderr → Yellow
// Missing key is treated as the default (disabled). Non-zero exits that do
// not look like "does not exist" are surfaced as errors rather than silently
// treated as disabled.


import Foundation

class BluetoothSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Bluetooth sharing disabled",
            description: "Check if Bluetooth Sharing is disabled",
            category: "CIS Benchmark",
            remediation: "Disable Bluetooth Sharing in System Settings",
            severity: "Medium",
            documentation: "Runs `defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled`. stdout 0 or a missing preference key is reported Green (disabled), 1 is Red (enabled), any other stdout is Yellow (unexpected value). Non-zero exits are only treated as \"missing key\" Green when stderr contains \"does not exist\"; other non-zero exits are reported Yellow with an error.",
            mitigation: "Disabling Bluetooth Sharing reduces the attack surface and helps prevent unauthorized access to your computer.",
            docID: 44, cisID: "2.3.3.10"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputString = String(
                data: outputPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines)

            if task.terminationStatus == 0 {
                switch outputString {
                case "0":
                    status = "Bluetooth Sharing is disabled"
                    checkstatus = "Green"
                case "1":
                    status = "Bluetooth Sharing is enabled"
                    checkstatus = "Red"
                case .some(let value) where !value.isEmpty:
                    status = "Unexpected Bluetooth Sharing value: \(value)"
                    checkstatus = "Yellow"
                default:
                    status = "Unexpected Bluetooth Sharing value: undecodable output"
                    checkstatus = "Yellow"
                }
            } else {
                let stderr = String(
                    data: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                    encoding: .utf8
                )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

                if stderr.contains("does not exist") {
                    status = "Bluetooth Sharing is disabled (default, preference key not set)"
                    checkstatus = "Green"
                } else {
                    let detail = stderr.isEmpty
                        ? "exit status \(task.terminationStatus)"
                        : stderr
                    let readError = NSError(
                        domain: "BluetoothSharingDisabledCheck",
                        code: Int(task.terminationStatus),
                        userInfo: [NSLocalizedDescriptionKey: "defaults read failed: \(detail)"]
                    )
                    print("Error checking \(name): \(readError)")
                    self.error = readError
                    status = "Error checking Bluetooth Sharing status: \(detail)"
                    checkstatus = "Yellow"
                }
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Bluetooth Sharing status"
            self.error = e
        }
    }
}
