//
//  GuestConnectCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class GuestConnectCheck: Vulnerability {
    init() {
        super.init(
            name: "Guest access to shared folders disabled",
            description: "This check ensures that the 'Allow guests to connect to shared folders' option is disabled on your system, which helps protect against unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > Users & Groups, click the info button next to Guest User, and turn off 'Allow guests to connect to shared folders'. Or run: sudo sysadminctl -smbGuestAccess off",
            severity: "Medium",
            documentation: "For more information on disabling 'Allow guests to connect to shared folders', visit: https://support.apple.com/guide/mac-help/share-mac-files-with-windows-users-mh14132/mac",
            mitigation: "By disabling 'Allow guests to connect to shared folders', you reduce the risk of unauthorized access to your computer's shared folders, enhancing its security.",
            docID: 31, cisID: "2.13.2"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/sysadminctl")
        task.arguments = ["-smbGuestAccess", "status"]

        // sysadminctl reports on stderr.
        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.contains("SMB guest access disabled") {
                status = "Guest access to shared folders is disabled"
                checkstatus = "Green"
            } else if output.contains("SMB guest access enabled") {
                status = "Guest access to shared folders is enabled"
                checkstatus = "Red"
            } else {
                status = "Unexpected sysadminctl output: \(output)"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking guest connect status"
        }
    }
}
