//
//  ExternalIntelligenceExtensionsCheck.swift
//  mergen
//
//  CIS 2.5.1.1 - Ensure External Intelligence Extensions Is Disabled

import Foundation

class ExternalIntelligenceExtensionsCheck: Vulnerability {
    init() {
        super.init(
            name: "Apple Intelligence External Extensions Disabled",
            description: "External Intelligence Extensions allow Apple Intelligence to interface with 3rd party generative AI tools (e.g. ChatGPT). Sending data to external services introduces additional risk.",
            category: "CIS Benchmark",
            remediation: "Create an MDM profile with PayloadType com.apple.applicationaccess, set allowExternalIntelligenceIntegrations to false and allowExternalIntelligenceIntegrationsSignIn to false.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.5.1.1",
            mitigation: "Disabling external intelligence extensions prevents organizational data from being sent to third-party AI providers.",
            checkstatus: "",
            docID: 101,
            cisID: "2.5.1.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-l", "JavaScript", "-e",
            "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowExternalIntelligenceIntegrations').js"]

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
                status = "External Intelligence Extensions are disabled."
                checkstatus = "Green"
            } else if output == "true" {
                status = "External Intelligence Extensions are enabled."
                checkstatus = "Red"
            } else {
                status = "No MDM profile found. External Intelligence Extensions state unknown."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Apple Intelligence external extensions"
        }
    }
}
