//
//  SafariInternetPluginCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class SafariInternetPluginsCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Safari Disable Internet Plugins for Global Use",
            description: "This check ensures that Internet plugins are disabled for global use in Safari, which helps prevent the execution of malicious code.",
            category: "Security",
            remediation: "To disable Internet plugins for global use in Safari, go to Safari > Preferences > Security, and uncheck the 'Allow Plug-ins' option.",
            severity: "Medium",
            documentation: "For more information on disabling Internet plugins for global use in Safari, visit: https://support.apple.com/guide/safari/preference-settings-for-security-ibrw1093/mac",
            mitigation: "By disabling Internet plugins for global use, you reduce the risk of malicious code execution through vulnerable plugins, enhancing your system's security.",
            docID: 34
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["read", "com.apple.Safari", "PlugInFirstVisitPolicy"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        do {
            try task.run()
            task.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.lowercased() == "2" {
                status = "Internet plugins are disabled for global use in Safari"
                checkstatus = "Green"
            } else {
                status = "Internet plugins are enabled for global use in Safari"
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Safari Internet plugins status"
            self.error = e
        }
    }
}

