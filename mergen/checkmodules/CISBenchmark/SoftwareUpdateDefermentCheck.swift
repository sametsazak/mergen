//
//  SoftwareUpdateDefermentCheck.swift
//  mergen
//
//  CIS 1.6 - Ensure Software Update Deferment Is Less Than or Equal to 30 Days

import Foundation

class SoftwareUpdateDefermentCheck: Vulnerability {
    init() {
        super.init(
            name: "Software Update Deferment ≤ 30 Days",
            description: "Software updates should not be deferred for more than 30 days. Attackers evaluate updates to create exploits against unpatched systems.",
            category: "CIS Benchmark",
            remediation: "Configure a MDM profile with PayloadType com.apple.applicationaccess and set enforcedSoftwareUpdateDelay to an integer ≤ 30. If no deferment profile is installed this check passes.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 1.6",
            mitigation: "Keeping update deferment within 30 days ensures security patches are applied promptly, reducing exploit windows.",
            checkstatus: "",
            docID: 100,
            cisID: "1.6"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('enforcedSoftwareUpdateDelay').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.isEmpty || output == "undefined" || output == "null" {
                status = "No update deferment policy installed — passes by default."
                checkstatus = "Green"
            } else if let days = Int(output), days <= 30 {
                status = "Software update deferment is set to \(days) days (≤ 30)."
                checkstatus = "Green"
            } else {
                status = "Software update deferment is set to \(output) days (> 30)."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking software update deferment"
        }
    }
}
