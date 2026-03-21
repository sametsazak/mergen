//
//  PasswordMinLengthCheck.swift
//  mergen
//
//  CIS 5.2.2 - Ensure Password Minimum Length Is Configured

import Foundation

class PasswordMinLengthCheck: Vulnerability {
    init() {
        super.init(
            name: "Password Minimum Length ≥ 15 Characters",
            description: "Passwords should have a minimum length of at least 15 characters to resist brute-force attacks.",
            category: "CIS Benchmark",
            remediation: "Run: sudo pwpolicy -n /Local/Default -setglobalpolicy 'minChars=15'. Or create an MDM profile with com.apple.mobiledevice.passwordpolicy and set minLength to 15.",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.2.2",
            mitigation: "Longer passwords exponentially increase the time required for brute-force attacks.",
            checkstatus: "",
            docID: 119,
            cisID: "5.2.2"
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

            // Check for minimum length in the policy
            if output.contains("policyAttributePassword matches") || output.contains("minimumLength") || output.contains("minChars") {
                // Try to extract the minimum length value
                let patterns = ["policyAttributePassword matches '.{(\\d+)}", "minimumLength.*?(\\d+)"]
                for pattern in patterns {
                    if let regex = try? NSRegularExpression(pattern: pattern),
                       let match = regex.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)),
                       match.numberOfRanges > 1,
                       let range = Range(match.range(at: 1), in: output),
                       let value = Int(output[range]) {
                        if value >= 15 {
                            status = "Password minimum length is \(value) characters (≥ 15)."
                            checkstatus = "Green"
                        } else {
                            status = "Password minimum length is \(value) characters (should be ≥ 15)."
                            checkstatus = "Red"
                        }
                        return
                    }
                }
                status = "Password length policy found but minimum length could not be parsed."
                checkstatus = "Yellow"
            } else {
                status = "No password minimum length policy configured."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking password minimum length"
        }
    }
}
