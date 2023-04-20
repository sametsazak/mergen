//
//  AirDropDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
//This script uses the ps aux command to check if the AirPlayXPCHelper process is running. If the process is running, it indicates that AirPlay Receiver is enabled; otherwise, it is disabled.
//Since this is not a certain way to understand Airplay is enabled, I couldn't find a solution except this. Based on CIS,         task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
// task.arguments = ["read", "com.apple.NetworkBrowser", "DisableAirDrop"]

class AirDropDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check AirDrop Is Disabled",
            description: "AirDrop is a convenient way to share files between Apple devices, but it can also pose a security risk if not used properly. This check verifies if AirDrop is disabled.",
            category: "CIS Benchmark",
            remediation: "To disable AirDrop, open Finder, click on 'Go' in the menu bar, select 'AirDrop', then click on 'Allow me to be discovered by:' and choose 'No One'.",
            severity: "Medium",
            documentation: "For more information about AirDrop and how to disable it, visit: https://support.apple.com/guide/mac-help/share-files-with-airdrop-mh17133/mac",
            mitigation: "Disabling AirDrop helps prevent unauthorized access to your computer and protects your data from being intercepted by unauthorized users. It is recommended to disable AirDrop when not in use and enable it only when needed.",
            checkstatus: "",
            docID: 13
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.NetworkBrowser", "DisableAirDrop"]
        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "AirDrop Is Disabled"
                checkstatus = "Green"
            } else {
                status = "AirDrop Is Enabled"
                checkstatus = "Red"
                
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking AirDrop status"
            self.error = e
        }
    }
}

