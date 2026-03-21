//
//  SpotlightImprovementCheck.swift
//  mergen
//
//  CIS 2.9.1 - Ensure Help Apple Improve Search Is Disabled

import Foundation

class SpotlightImprovementCheck: Vulnerability {
    init() {
        super.init(
            name: "Spotlight 'Help Apple Improve Search' Is Disabled",
            description: "Apple provides a mechanism to send Spotlight search metadata back to Apple. Information sent may contain internal organizational data that should be controlled.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.assistant.support and set 'Search Queries Data Sharing Status' to 2 (integer).",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.9.1",
            mitigation: "Disabling search query sharing prevents Spotlight metadata from being forwarded to Apple.",
            checkstatus: "",
            docID: 110,
            cisID: "2.9.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support').objectForKey('Search Queries Data Sharing Status').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "2" {
                status = "Help Apple Improve Search is disabled."
                checkstatus = "Green"
            } else if output.isEmpty || output == "undefined" || output == "null" || output == "1" {
                status = "Help Apple Improve Search may be enabled (status: \(output.isEmpty ? "not set" : output))."
                checkstatus = "Red"
            } else {
                status = "Spotlight improvement status unknown."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Spotlight improvement setting"
        }
    }
}
