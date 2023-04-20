//
//  GuestLoginCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)

//Checks if the Guest account is disabled by running the defaults command and reading the GuestEnabled setting. If the value is "0", it means the Guest account is disabled, and the check status will be "Green". If the value is not "0", it means the Guest account is enabled, and the check status will be "Red". If there's an error parsing the output or running the command, the check status will be "Yellow".

import Foundation

class GuestLoginCheck: Vulnerability {
    init() {
        super.init(
            name: "Guest Login Status Check",
            description: "Verify that guest login is disabled to protect your Mac from unauthorized access",
            category: "CIS Benchmark",
            remediation: "Disable guest login by going to System Preferences > Users & Groups > Guest User and unchecking 'Allow guests to log in to this computer'",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/set-up-other-users-on-your-mac-mtusr001/mac",
            mitigation: "Disabling guest login minimizes the risk of unauthorized access to your Mac by preventing users without a valid account from logging in.",
            checkstatus: "",
            docID: 2
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.loginwindow.plist", "GuestEnabled"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Guest Login is Enabled."
                checkstatus = "Red"
            } else {
                status = "Guest Login is Disabled."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            self.checkstatus = "Yellow"
            status = "Error checking guest login status"
        }
    }
}
