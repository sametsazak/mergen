//
//  PasswordLockoutThresholdCheck.swift
//  mergen
//
//  CIS 5.2.1 - Ensure Password Account Lockout Threshold Is Configured

import Foundation

class PasswordLockoutThresholdCheck: Vulnerability {
    init() {
        super.init(
            name: "Password Lockout Threshold ≤ 5 Attempts",
            description: "The account should lock after 5 or fewer failed login attempts to prevent brute-force password attacks.",
            category: "CIS Benchmark",
            remediation: "Run: sudo pwpolicy -n /Local/Default -setglobalpolicy 'maxFailedLoginAttempts=5'. Or create an MDM profile with com.apple.mobiledevice.passwordpolicy and set maxFailedAttempts to 5.",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.2.1",
            mitigation: "Account lockout after repeated failed attempts prevents brute-force attacks on user credentials.",
            checkstatus: "",
            docID: 118,
            cisID: "5.2.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pwpolicy")
        task.arguments = ["-getaccountpolicies"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if output.contains("policyAttributeMaximumFailedAuthentications") {
                // Extract the value using a simple search
                if let range = output.range(of: "policyAttributeMaximumFailedAuthentications") {
                    let after = String(output[range.upperBound...])
                    if let intRange = after.range(of: "<integer>"),
                       let endRange = after.range(of: "</integer>") {
                        let valueStr = String(after[intRange.upperBound..<endRange.lowerBound])
                        if let value = Int(valueStr) {
                            if value <= 5 {
                                status = "Password lockout threshold is \(value) (≤ 5)."
                                checkstatus = "Green"
                            } else {
                                status = "Password lockout threshold is \(value) (should be ≤ 5)."
                                checkstatus = "Red"
                            }
                            return
                        }
                    }
                }
                status = "Password lockout policy found but value could not be parsed."
                checkstatus = "Yellow"
            } else {
                status = "No password lockout threshold configured."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking password lockout threshold"
        }
    }
}
