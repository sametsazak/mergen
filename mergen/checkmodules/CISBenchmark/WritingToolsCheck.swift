//
//  WritingToolsCheck.swift
//  mergen
//
//  CIS 2.5.1.2 - Ensure Writing Tools Is Disabled

import Foundation

class WritingToolsCheck: Vulnerability {
    init() {
        super.init(
            name: "Apple Intelligence Writing Tools Disabled",
            description: "Apple Intelligence Writing Tools use AI to enhance text. While mostly on-device, they may leverage Apple's private cloud infrastructure. Organizations handling sensitive data should disable this.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess and set allowWritingTools to false.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.5.1.2",
            mitigation: "Disabling Writing Tools prevents text content from potentially being sent off-device for AI processing.",
            checkstatus: "",
            docID: 102,
            cisID: "2.5.1.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowWritingTools').js"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "false" {
                status = "Writing Tools are disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "Writing Tools are enabled."
                checkstatus = "Red"
            } else {
                status = "No MDM profile found. Writing Tools state unknown."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Apple Intelligence Writing Tools"
        }
    }
}
