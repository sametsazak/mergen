//
//  BluetoothSharingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//This check runs the defaults read command with the com.apple.Bluetooth domain and the PrefKeyServicesEnabled key to check the status of Bluetooth Sharing. If the value of the key is 0, it sets the status to "Bluetooth Sharing is Disabled" and the check status to "Green". If the value of the key is anything else, it sets the status to "Bluetooth Sharing is Enabled" and the check status to "Red".


import Foundation

class BluetoothSharingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Bluetooth Sharing Is Disabled",
            description: "Check if Bluetooth Sharing is disabled",
            category: "CIS Benchmark",
            remediation: "Disable Bluetooth Sharing in System Preferences",
            severity: "Medium",
            documentation: "This check runs the defaults read command with the com.apple.Bluetooth domain and the PrefKeyServicesEnabled key to check the status of Bluetooth Sharing. If the value of the key is 0, it sets the status to 'Bluetooth Sharing is Disabled'",
            mitigation: "Disabling Bluetooth Sharing reduces the attack surface and helps prevent unauthorized access to your computer.",
            docID: 44
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                if outputString == "0" {
                    status = "Bluetooth Sharing is Disabled"
                    checkstatus = "Green"
                } else {
                    status = "Bluetooth Sharing is Enabled"
                    checkstatus = "Red"
                }
            } else {
                status = "Error checking Bluetooth Sharing status"
                checkstatus = "Yellow"
                self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Bluetooth Sharing status"
            self.error = e
            print(e)
        }
    }
}
