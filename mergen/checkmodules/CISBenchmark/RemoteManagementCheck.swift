//
//  RemoteManagementCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

//This implementation uses two separate processes to execute the ps and grep commands, and passes output from the first process to the second process using a pipe. The grep command searches the output for the ARDAgent process, which is an indicator that Remote Management is enabled.

class RemoteManagementDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Remote Management(ARDagent) Is Disabled",
            description: "This check ensures that the Remote Management (ARDagent) feature is disabled to prevent unauthorized access to your computer.",
            category: "CIS Benchmark",
            remediation: "To disable Remote Management, go to System Preferences > Sharing and uncheck the 'Remote Management' option.",
            severity: "Medium",
            documentation: "https://support.apple.com/guide/mac-help/remote-management-mh14074/mac",
            mitigation: "Disabling Remote Management minimizes the risk of unauthorized access to your computer by reducing the ways an attacker can remotely control your system.",
            docID: 39
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["-ef"]
        
        let grepTask = Process()
        grepTask.executableURL = URL(fileURLWithPath: "/usr/bin/grep")
        grepTask.arguments = ["-e", "ARDAgent", "-v", "grep"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        grepTask.standardInput = pipe
        
        do {
            try task.run()
            try grepTask.run()
            task.waitUntilExit()
            grepTask.waitUntilExit()
            
            if grepTask.terminationStatus == 0 {
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
