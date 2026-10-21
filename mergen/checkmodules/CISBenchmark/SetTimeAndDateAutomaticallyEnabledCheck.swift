//
//  SetTimeAndDateAutomaticallyEnabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SetTimeAndDateAutomaticallyEnabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Time set automatically",
            description: "This check ensures that your computer sets its date and time automatically from a network time server. This helps maintain accurate timekeeping and prevent potential security issues.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > General > Date & Time and turn on 'Set time and date automatically'. Or run: sudo systemsetup -setnetworktimeserver time.apple.com && sudo systemsetup -setusingnetworktime on",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/set-the-date-and-time-mh35851/mac",
            mitigation: "Keeping your computer's date and time accurate helps ensure proper functioning of the system and its applications. It also helps avoid potential security issues related to incorrect timekeeping.",
            docID: 15, cisID: "2.3.2.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/systemsetup")
        task.arguments = ["-getusingnetworktime"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            // Without root, systemsetup exits 0 and prints a notice instead of the setting.
            if output.range(of: "Network Time:\\s*On\\b", options: .regularExpression) != nil {
                status = "Set Time and Date Automatically is Enabled"
                checkstatus = "Green"
            } else if output.range(of: "Network Time:\\s*Off\\b", options: .regularExpression) != nil {
                status = "Set Time and Date Automatically is Disabled"
                checkstatus = "Red"
            } else if output.contains("administrator access") {
                status = "Administrator privileges are required to read this setting. Run: sudo systemsetup -getusingnetworktime"
                checkstatus = "Yellow"
            } else {
                status = "Unexpected systemsetup output: \(output)"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Set Time and Date Automatically status"
            self.error = e
        }
    }
}
