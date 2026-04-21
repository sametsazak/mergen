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

            // pwpolicy emits length predicates as:
            //   policyAttributePassword matches '.{15,}'     (rare)
            //   policyAttributePassword matches '.{15,}?'    (common)
            //   policyAttributePassword matches '.{15,}+'    (common)
            // A single policy may stack several such predicates (e.g. .{15,}? for
            // min length AND .{4,}+ for "at least 4 alphanumeric chars"). The
            // effective minimum length is the MAX N across all matches.
            let lengthPattern = "policyAttributePassword matches '\\.\\{(\\d+),\\}[?+]?'"
            var lengths: [Int] = []
            if let regex = try? NSRegularExpression(pattern: lengthPattern) {
                let range = NSRange(output.startIndex..., in: output)
                for match in regex.matches(in: output, range: range) where match.numberOfRanges > 1 {
                    if let r = Range(match.range(at: 1), in: output),
                       let n = Int(output[r]) {
                        lengths.append(n)
                    }
                }
            }

            // Fallback: older/MDM-style profile keys.
            if lengths.isEmpty {
                let fallbackPatterns = ["minimumLength\\D+(\\d+)", "minChars\\D+(\\d+)"]
                for pattern in fallbackPatterns {
                    if let regex = try? NSRegularExpression(pattern: pattern) {
                        let range = NSRange(output.startIndex..., in: output)
                        for match in regex.matches(in: output, range: range) where match.numberOfRanges > 1 {
                            if let r = Range(match.range(at: 1), in: output),
                               let n = Int(output[r]) {
                                lengths.append(n)
                            }
                        }
                    }
                }
            }

            if let maxLen = lengths.max() {
                if maxLen >= 15 {
                    status = "Minimum length: \(maxLen)"
                    checkstatus = "Green"
                } else {
                    status = "Minimum length: \(maxLen) (< 15 required)"
                    checkstatus = "Red"
                }
            } else if output.contains("policyAttributePassword matches") || output.contains("minimumLength") || output.contains("minChars") {
                status = "Password length policy found but no minimum-length predicate could be parsed from pwpolicy output."
                checkstatus = "Yellow"
            } else {
                status = "No minimum-length policy detected in pwpolicy output."
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
