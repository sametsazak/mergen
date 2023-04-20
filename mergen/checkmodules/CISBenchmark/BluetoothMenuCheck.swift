//
//  BluetoothMenuCheck.swift
//  mergen
//
//  Created by Samet Sazak
//


import Foundation

class BluetoothMenuBarCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Show Bluetooth Status in Menu Bar Is Enabled",
            description: "This check ensures that the Bluetooth menu bar icon is displayed, allowing you to quickly check the status of your Bluetooth devices and disconnect any devices that you're not using.",
            category: "CIS Benchmark",
            remediation: "To enable 'Show Bluetooth in menu bar', go to System Preferences > Bluetooth and check the option.",
            severity: "Low",
            documentation: "For more information on how to use Bluetooth devices with your Mac, visit: https://support.apple.com/guide/mac-help/use-bluetooth-devices-mchlpt1030/mac",
            mitigation: "Displaying the Bluetooth menu bar icon helps you quickly monitor and manage your Bluetooth devices.",
            docID: 49
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.controlcenter.plist", "NSStatusItem Visible Bluetooth"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                if outputString == "1" {
                    status = "Show Bluetooth Status in Menu Bar is Enabled"
                    checkstatus = "Green"
                } else {
                    status = "Show Bluetooth Status in Menu Bar is Disabled"
                    checkstatus = "Red"
                }
            } else {
                status = "Error checking Show Bluetooth Status in Menu Bar status"
                checkstatus = "Yellow"
                self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Show Bluetooth Status in Menu Bar status"
            self.error = e
            print(e)
        }
    }
}

