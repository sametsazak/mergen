//
//  BonjourCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class BonjourCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Bonjour Advertising Service Status",
            description: "Check if Bonjour advertising service is disabled. Bonjour is a service that helps devices and applications discover each other on a local network. Disabling it can help prevent unauthorized access to your computer.",
            category: "Security",
            remediation: "Disable Bonjour advertising service by going to System Preferences > Sharing and unchecking all sharing services.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/set-up-file-sharing-on-mac-mchlp1657/mac",
            mitigation: "Disabling Bonjour advertising service reduces the attack surface and helps prevent unauthorized access to your computer.",
            checkstatus: "",
            docID: 27
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.mDNSResponder.plist", "NoMulticastAdvertisements"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Bonjour service is not running."
                checkstatus = "Green"
            } else {
                status = "Bonjour service is running."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Bonjour status"
        }
    }
}

