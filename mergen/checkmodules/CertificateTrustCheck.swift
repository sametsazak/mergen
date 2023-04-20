//
//  CertificateTrustCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class CertificateTrustCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Certificate Trust Settings",
            description: "Check for potential issues with trusted certificates",
            category: "Security",
            remediation: "Review certificate trust settings and remove any untrusted or expired certificates",
            severity: "High",
            documentation: "This code checks the trust settings of certificates on your system. Trust settings determine whether your computer trusts specific certificates, such as those used for secure websites. Untrusted or expired certificates can pose security risks, such as allowing unauthorized access to sensitive information.",
            mitigation: "Review the certificate trust settings on your system and remove any untrusted or expired certificates. You can do this by opening Keychain Access, navigating to the 'Certificates' category, and inspecting the certificates listed. Look for any certificates marked as 'untrusted' or 'expired' and remove them.",
            checkstatus: "",
            docID: 22
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["dump-trust-settings"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        let errorPipe = Pipe()
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            
            print("Output: \(output)")
            
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorOutput = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            print("errorData: \(errorData)")
            print("errorOutput: \(errorOutput)")
            if output.contains("No Trust Settings were found.") || errorOutput.contains("No Trust Settings were found.") {
                status = "Certificate trust is OK."
                checkstatus = "Green"
            } else {
                status = "Certificate trust issues found"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
        }
    }
}
