//
//  SecureKernelExtensionLoadingCheck.swift
//  mergen
//
//  Created by Samet Sazak
//
//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class SecureKernelExtensionLoadingCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Secure Kernel Extension Loading",
            description: "Verify that Secure Kernel Extension Loading is enabled to protect your Mac from potentially harmful kernel extensions",
            category: "CIS Benchmark",
            remediation: "Enable Secure Kernel Extension Loading by booting into Recovery Mode, opening Terminal, and running 'csrutil enable', then restart your Mac",
            severity: "Medium",
            documentation: "https://support.apple.com/en-us/HT204899",
            mitigation: "Secure Kernel Extension Loading prevents unsigned kernel extensions from being loaded, providing an additional layer of security against potentially malicious software.",
            checkstatus: "",
            docID: 1
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["csrutil", "status"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            task.waitUntilExit()
            
            if task.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                if let output = String(data: data, encoding: .utf8) {
                    if output.contains("enabled") {
                        status = "Secure Kernel Extension Loading is Enabled"
                        checkstatus = "Green"
                    } else {
                        status = "Secure Kernel Extension Loading is Disabled"
                        checkstatus = "Red"
                    }
                } else {
                    status = "Error parsing Secure Kernel Extension Loading status"
                    checkstatus = "Yellow"
                }
            } else {
                status = "Error checking Secure Kernel Extension Loading status (requires root privileges)"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Secure Kernel Extension Loading status"
            self.error = e
        }
    }
}
