//
//  WakeForNetworkAccessCheck.swift
//  mergen
//
//  Created by Samet Sazak
//


//This script checks if the value of "womp" is 0 in the output of pmset command and sets the status accordingly.


import Foundation

class WakeForNetworkAccessCheck: Vulnerability {

    init() {
        super.init(
            name: "Wake for network access disabled",
            description: "Checks if Wake for Network Access is disabled to prevent unauthorized access",
            category: "CIS Benchmark",
            remediation: "To disable Wake for Network Access, open Terminal and run the following command:\n\nsudo pmset -a womp 0\n\nThis command disables Wake for Network Access for both battery and AC power.",
            severity: "Low",
            documentation: "This code verifies if Wake for Network Access is disabled on your system. When enabled, Wake for Network Access may allow unauthorized access to your system and potentially expose sensitive data.",
            mitigation: "To protect your system, disable Wake for Network Access, ensuring that only authorized devices can connect.",
            docID: 56, cisID: "2.10.3"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
        task.arguments = ["-g", "custom"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let lines = output.components(separatedBy: .newlines)

            // All womp lines must be 0 — any line with womp 1 means Wake for Network is on
            let wompLines = lines.filter { $0.contains("womp") }
            let anyEnabled = wompLines.contains { $0.contains("1") }

            if wompLines.isEmpty {
                status = "Wake for Network Access setting not found (may not apply to this hardware)."
                checkstatus = "Yellow"
            } else if anyEnabled {
                status = "Wake for Network Access is enabled for at least one power mode."
                checkstatus = "Red"
            } else {
                status = "Wake for Network Access is disabled for all power modes."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Wake for Network Access status"
            self.error = e
        }
    }
}
