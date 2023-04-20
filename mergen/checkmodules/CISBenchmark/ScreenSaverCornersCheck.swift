//
//  ScreenSaverCornersCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class ScreenSaverCornersCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Screen Saver Corners Are Secure",
            description: "This check ensures that Screen Saver Corners are set to a secure option, preventing the screen saver from being easily deactivated and reducing potential security risks.",
            category: "CIS Benchmark",
            remediation: "To set Screen Saver Corners to a secure option, go to System Preferences > Desktop & Screen Saver > Screen Saver > Hot Corners and select secure options for each corner.",
            severity: "Low",
            documentation: "Setting secure options for Screen Saver Corners helps prevent unauthorized access to your computer when the screen saver is active.",
            mitigation: "Configuring Screen Saver Corners with secure options ensures that the screen saver can only be deactivated using a secure method, enhancing the security of your system.",
            docID: 54
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/defaults"
        task.arguments = ["read", "com.apple.dock", "wvous-tl-corner", "wvous-tr-corner", "wvous-bl-corner", "wvous-br-corner"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                let corners = output.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: "\n")
                if corners.contains("5") && corners.contains("6") && corners.contains("10") && corners.contains("11") {
                    status = "Screen Saver Corners are set to a secure option"
                    checkstatus = "Green"
                } else {
                    status = "Screen Saver Corners are not set to a secure option"
                    checkstatus = "Red"
                }
            } else {
                status = "Error parsing Screen Saver Corners status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Screen Saver Corners status"
            self.error = e
        }
    }
}

