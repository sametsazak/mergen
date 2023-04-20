//
//  AppSandboxCheck.swift
//  mergen
//
//  Created by Samet Sazak on 27.03.2023.
//

import Foundation

class AppSandboxCheck: Vulnerability {
    init() {
        super.init(
            name: "App Sandbox Check",
            description: "Check if App Sandbox is enabled for the current app",
            category: "Security",
            remediation: "Enable App Sandbox for the app using the entitlements file",
            severity: "High",
            documentation: "https://developer.apple.com/documentation/security/app_sandbox",
            mitigation: "Enable App Sandbox for the app"
        )
    }
    
    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        task.arguments = ["--display", "--entitlements", ":-", Bundle.main.bundlePath]
        
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8) ?? ""
            let entitlements = try PropertyListSerialization.propertyList(from: output.data(using: .utf8)!, options: [], format: nil) as? [String: Any]
            print("Entitlements: \(entitlements ?? [:])")
            if let sandbox = entitlements?["com.apple.security.app-sandbox"] as? Bool {
                if sandbox {
                    status = "Not Vulnerable"
                } else {
                    status = "App Sandbox not enabled"
                }
            } else {
                status = "Unknown"
            }
        } catch let e {
            print("Error checking App Sandbox: \(e)")
            self.error = e
        }
    }
}

