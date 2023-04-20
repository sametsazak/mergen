//
//  PrinterSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class PrinterSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Printer Sharing Is Disabled",
            description: "Printer Sharing allows you to share printers with other users over a network. This check ensures that Printer Sharing is disabled to prevent unauthorized access to your printers.",
            category: "CIS Benchmark",
            remediation: "To disable Printer Sharing, go to 'System Preferences', click on 'Sharing', and uncheck the 'Printer Sharing' option.",
            severity: "Medium",
            documentation: "For more information about Printer Sharing and how to disable it, visit: https://support.apple.com/guide/mac-help/share-mac-printers-with-other-users-mchlp1011/mac",
            mitigation: "Disabling Printer Sharing reduces the risk of unauthorized access to your printers and printer resources. This minimizes the ways an attacker can connect to your system and helps protect your printer resources from unauthorized access.",
            docID: 37
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/cupsctl")
        
        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.contains("_share_printers=1") {
                    status = "Printer Sharing is Enabled"
                    checkstatus = "Red"
                } else {
                    status = "Printer Sharing is Disabled"
                    checkstatus = "Green"
                }
            } else {
                status = "Error parsing Printer Sharing status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Printer Sharing status"
            self.error = e
        }
    }
}
