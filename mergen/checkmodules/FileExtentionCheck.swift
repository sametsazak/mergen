//
//  FileExtentionCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class FilenameExtensionsCheck: Vulnerability {
    init() {
        super.init(
            name: "Filename extensions shown",
            description: "This check ensures that filename extensions are turned on in your system, which helps prevent users from accidentally running malicious files.",
            category: "CIS Benchmark",
            remediation: "To turn on filename extensions, go to Finder > Preferences > Advanced, and check the 'Show all filename extensions' option.",
            severity: "Low",
            documentation: "For more information on turning on filename extensions, visit: https://support.apple.com/guide/mac-help/show-or-hide-filename-extensions-on-mac-mh26782/mac",
            mitigation: "By turning on filename extensions, you help users identify and avoid accidentally running malicious files, enhancing the system's security.",
            docID: 32, cisID: "6.1.1"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "NSGlobalDomain", "AppleShowAllExtensions"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "1" {
                status = "Filename extension is enabled."
                checkstatus = "Green"
            } else {
                status = "Filename extensions are hidden."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            status = "Error checking filename extensions status"
            checkstatus = "Yellow"
            self.error = e
        }
    }
}
