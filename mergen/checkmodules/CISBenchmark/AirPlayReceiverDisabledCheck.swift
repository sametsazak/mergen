//
//  AirPlayReceiverDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//


import Foundation

class AirPlayReceiverDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "AirPlay Receiver disabled",
            description: "AirPlay Receiver allows you to mirror your Mac's screen on other devices, like Apple TV. This check verifies if AirPlay Receiver is disabled.",
            category: "CIS Benchmark",
            remediation: "To disable AirPlay Receiver, go to 'System Settings', click on 'Displays', and uncheck 'Show mirroring options in the menu bar when available'.",
            severity: "Medium",
            documentation: "For more information about AirPlay Receiver and how to disable it, visit: https://support.apple.com/guide/mac-help/mirror-the-screen-on-a-mac-with-mirroring-display-preferences-mh14127/mac",
            mitigation: "Disabling AirPlay Receiver reduces the risk of unauthorized access to your computer by preventing unauthorized users from mirroring your Mac's screen on their devices. It is recommended to disable AirPlay Receiver when not in use.",
            checkstatus: "",
            docID: 14, cisID: "2.3.1.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.controlcenter", "AirplayRecieverEnabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "0" || task.terminationStatus != 0 {
                status = "AirPlay Receiver is Disabled"
                checkstatus = "Green"
            } else {
                status = "AirPlay Receiver is Enabled"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking AirPlay Receiver status"
            self.error = e
        }
    }
}

