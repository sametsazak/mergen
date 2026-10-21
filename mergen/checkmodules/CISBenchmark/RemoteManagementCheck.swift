//
//  RemoteManagementCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

// Remote Management is on while the ARDAgent process runs, so the check looks for its binary in `ps -ef` output.

class RemoteManagementDisabledCheck: Vulnerability {
    private static let ardAgentPath = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"

    init() {
        super.init(
            name: "Remote management disabled",
            description: "This check ensures that the Remote Management (ARDagent) feature is disabled to prevent unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "Go to System Settings > General > Sharing and turn off 'Remote Management'. Or run: sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/remote-management-mh14074/mac",
            mitigation: "Disabling Remote Management minimizes the risk of unauthorized access to your computer by reducing the ways an attacker can remotely control your system.",
            docID: 39, cisID: "2.3.3.5"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["-ef"]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = Pipe()

        do {
            try task.run()
            // Read before waiting: the process list can exceed the pipe buffer.
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()

            let output = String(data: outputData, encoding: .utf8) ?? ""

            if task.terminationStatus != 0 {
                status = "Error checking Remote Management status (ps exited with \(task.terminationStatus))"
                checkstatus = "Yellow"
            } else if output.contains(Self.ardAgentPath) {
                status = "Remote Management is Enabled"
                checkstatus = "Red"
            } else {
                status = "Remote Management is Disabled"
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking Remote Management status"
            self.error = e
        }
    }
}
