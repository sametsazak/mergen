//
//  FileVaultCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

import Foundation

class FileVaultCheck: Vulnerability {
    init() {
        super.init(
            name: "Check FileVault Status",
            description: "FileVault is a built-in disk encryption feature on macOS. This check verifies if FileVault is enabled or disabled on your device.",
            category: "CIS Benchmark",
            remediation: "To enable FileVault, go to System Preferences -> Security & Privacy -> FileVault, and click 'Turn On FileVault...'",
            severity: "High",
            documentation: "For more information about FileVault, visit: https://support.apple.com/en-us/HT204837",
            mitigation: "Enabling FileVault helps protect your data by encrypting your disk. If your computer is lost or stolen, unauthorized users will have difficulty accessing your data.",
            checkstatus: "",
            docID: 6
        )
    }
    
    override func check() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["bash", "-c", "fdesetup status"]
        
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8) ?? ""
            
            if output.contains("FileVault is On") {
                self.status = "FileVault is enabled."
                self.checkstatus = "Green"
            } else {
                self.status = "FileVault is Disabled."
                self.checkstatus = "Red"
            }
        } catch {
            print("Error checking FileVault status: \(error)")
            self.checkstatus = "Yellow"
            status = "Error checking FileVault status"
        }
    }
}

