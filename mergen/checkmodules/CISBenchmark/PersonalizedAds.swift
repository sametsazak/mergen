//
//  PersonalizedAds.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class LimitAdTrackingCheck: Vulnerability {
    init() {
        super.init(
            name: "Personalized ads disabled",
            description: "This check ensures that Personalized Ads are disabled on your system, which helps protect your privacy by preventing advertisers from displaying targeted ads based on your interests and usage.",
            category: "CIS Benchmark",
            remediation: "To disable Personalized Ads, enable Limit Ad Tracking in System Settings > Security & Privacy > Privacy > Advertising.",
            severity: "Low",
            documentation: "For more information on how to limit ad tracking, visit: https://support.apple.com/en-us/HT205223",
            mitigation: "Disabling Personalized Ads by enabling Limit Ad Tracking helps protect your privacy and limits the information shared with advertisers.",
            docID: 52, cisID: "2.6.4"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.AdLib", "allowApplePersonalizedAdvertising"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.contains("1") {
                    status = "Personalized Ads are enabled."
                    checkstatus = "Red"
                } else {
                    status = "Personalized Ads are disabled"
                    checkstatus = "Green"
                }
            } else {
                status = "Error parsing Personalized Ads status."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Personalized Ads status"
            self.error = e
        }
    }
}
