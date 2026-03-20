//
//  LoginWindowNamePasswordCheck.swift
//  mergen
//
//  CIS 2.11.4 - Ensure Login Window Displays as Name and Password Is Enabled

import Foundation

class LoginWindowNamePasswordCheck: Vulnerability {
    init() {
        super.init(
            name: "Login Window Shows Name and Password",
            description: "When the login window prompts for both username and password (rather than showing a list of users), unauthorized access becomes harder since an attacker must discover two attributes.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Lock Screen and set 'Login window shows' to 'Name and Password'. Or run: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.11.4",
            mitigation: "Requiring both username and password input at login increases difficulty for unauthorized access attempts.",
            checkstatus: "",
            docID: 114,
            cisID: "2.11.4"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        task.arguments = ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output == "1" {
                status = "Login window shows name and password fields."
                checkstatus = "Green"
            } else {
                status = "Login window shows user list instead of name and password."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking login window display setting"
        }
    }
}
