//
//  ShowWifiMenuCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

//This script checks if the AirPort.menu is included in the menuExtras property of the com.apple.systemuiserver domain in the defaults command output. If it is present, then the Wi-Fi status is shown in the menu bar and the check passes. Otherwise, the check fails.

class ShowWiFiStatusCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Show Wi-Fi status in Menu Bar Is Enabled",
            description: "This check ensures that the Wi-Fi status is shown in the menu bar, allowing you to quickly check the Wi-Fi status and connect to available networks.",
            category: "CIS Benchmark",
            remediation: "To enable 'Show Wi-Fi status in menu bar', go to System Preferences > Network and check the option.",
            severity: "Low",
            documentation: "For more information on how to use the Wi-Fi status menu, visit: https://support.apple.com/guide/mac-help/use-the-wi-fi-status-menu-mchlp1540/mac",
            mitigation: "Displaying Wi-Fi status in the menu bar provides an accessible way to monitor your connection and manage Wi-Fi networks.",
            docID: 48
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.systemuiserver", "menuExtras"]
        
        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)
                if outputString?.contains("AirPort.menu") == true {
                    status = "Show Wi-Fi status in menu bar is Enabled"
                    checkstatus = "Green"
                } else {
                    status = "Show Wi-Fi status in menu bar is Disabled"
                    checkstatus = "Red"
                }
            } else {
                status = "Error checking Wi-Fi status"
                checkstatus = "Yellow"
                self.error = NSError(domain: NSPOSIXErrorDomain, code: Int(task.terminationStatus), userInfo: nil)
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Wi-Fi status"
            self.error = e
        }
    }
}

