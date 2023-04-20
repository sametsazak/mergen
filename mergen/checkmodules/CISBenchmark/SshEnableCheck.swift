//
//  SshEnableCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

//Tested in 13-inch, 2020, Four Thunderbolt 3 ports 13.2.1 (22D68)
import Foundation

class SSHCheck: Vulnerability {
    init() {
        super.init(
            name: "Check If SSH Is Enabled",
            description: "Check if SSH is enabled and running",
            category: "CIS Benchmark",
            remediation: "Disable SSH or configure it securely by following the recommended practices",
            severity: "High",
            documentation: "https://support.apple.com/guide/mac-help/use-remote-login-mchlp1066/mac",
            mitigation: "Disabling SSH, if not needed, or configuring it securely reduces the attack surface and helps prevent unauthorized access to your computer. Follow best practices for secure SSH configuration, such as using strong authentication methods and limiting access to specific users.",
            checkstatus: "",
            docID: 4
        )
    }
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["print-disabled", "system"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            if task.terminationStatus == 0 {
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let outputString = String(data: outputData, encoding: .utf8)

                if let outputString = outputString, outputString.contains("\"com.openssh.sshd\" => disabled") {
                    status = "SSH is Disabled"
                    checkstatus = "Green"
                } else {
                    status = "SSH is Enabled"
                    checkstatus = "Red"
                }
            } else {
                status = "Error checking Remote Apple Events status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Remote Apple Events status"
            self.error = e
            print(e)
        }
    }
}
