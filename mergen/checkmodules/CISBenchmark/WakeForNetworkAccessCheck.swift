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
            name: "Check Wake for Network Access is Disabled",
            description: "Checks if Wake for Network Access is disabled to prevent unauthorized access",
            category: "CIS Benchmark",
            remediation: "To disable Wake for Network Access, open Terminal and run the following command:\n\nsudo pmset -a womp 0\n\nThis command disables Wake for Network Access for both battery and AC power.",
            severity: "Low",
            documentation: "This code verifies if Wake for Network Access is disabled on your system. When enabled, Wake for Network Access may allow unauthorized access to your system and potentially expose sensitive data.",
            mitigation: "To protect your system, disable Wake for Network Access, ensuring that only authorized devices can connect.",
            docID: 56
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/pmset"
        task.arguments = ["-g"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                let lines = output.components(separatedBy: .newlines)
                var batteryWomp = false
                for line in lines {
                    if line.contains("womp") && line.contains("0") {
                        batteryWomp = true
                    }
                }
                if batteryWomp {
                    status = "Wake for Network Access is disabled for both battery and AC power"
                    checkstatus = "Green"
                } else {
                    status = "Wake for Network Access is enabled for at least one power mode"
                    checkstatus = "Red"
                }
            } else {
                status = "Error parsing pmset output"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Wake for Network Access status"
            self.error = e
        }
    }
}
