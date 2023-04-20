//
//  AppleSoftwareUpdateCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class AppleSoftwareUpdateCheck: Vulnerability {
    init() {
        super.init(
            name: "Check All Apple-Provided Software Is Updated In Last 30 Days",
            description: "Checks if all Apple-provided software is up-to-date using the Software Update tool.",
            category: "CIS Benchmark",
            remediation: "Run the Software Update tool to install the latest security patches and software updates from Apple.",
            severity: "High",
            documentation: "https://support.apple.com/en-us/HT201541",
            mitigation: "Regularly updating all Apple-provided software helps prevent unauthorized access and minimizes the risk of known vulnerabilities being exploited.",
            checkstatus: "",
            docID: 7
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastFullSuccessfulDate"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"

            if let lastUpdateDate = dateFormatter.date(from: output) {
                let daysSinceLastUpdate = Calendar.current.dateComponents([.day], from: lastUpdateDate, to: Date()).day ?? 0

                if daysSinceLastUpdate <= 30 {
                    status = "Apple-provided Software is Updated in the last 30 days."
                    checkstatus = "Green"
                } else {
                    status = "Apple-provided Software is NOT Updated In The Last 30 days."
                    checkstatus = "Red"
                }
            } else {
                status = "Apple-provided Software is NOT Updated In The Last 30 days."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Apple software update status"
        }
    }
}
