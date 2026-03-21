//
//  ContentCachingDisabledCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation


//The main use case for Mac computers is as mobile user endpoints. P2P sharing
//services should not be enabled on laptops that are using untrusted networks. Content
//Caching can allow a computer to be a server for local nodes on an untrusted network.
//While there are certainly logical controls that could be used to mitigate risk, they add to
//the management complexity. Since the value of the service is in specific use cases
//organizations with the use case described above can accept risk as necessary.
                                                    
                                                    
class ContentCachingDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Content caching disabled",
            description: "This check ensures that Content Caching is disabled to prevent your computer from being a server on untrusted networks, which could expose it to unauthorized access.",
            category: "CIS Benchmark",
            remediation: "To disable Content Caching, go to System Settings > Sharing and uncheck the 'Content Caching' option.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/use-content-caching-on-mac-mchl7f772b81/mac",
            mitigation: "Disabling Content Caching lowers the risk of unauthorized access to your computer by reducing the ways an attacker can access cached content from your system.",
            docID: 42, cisID: "2.3.3.8"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "/Library/Preferences/com.apple.AssetCache.plist", "Activated"]

        do {
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
        task.standardError = Pipe()
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let outputString = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)

            if task.terminationStatus != 0 || outputString == nil || outputString == "" {
                // Plist absent = Content Caching has never been activated.
                status = "Content Caching is disabled."
                checkstatus = "Green"
            } else if outputString == "1" {
                status = "Content Caching is enabled."
                checkstatus = "Red"
            } else {
                status = "Content Caching is disabled."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Content Caching status"
            self.error = e
        }
    }
}

