//
//  RootAccountDisabledCheck.swift
//  mergen
//
//  CIS 5.6 - Ensure the "root" Account Is Disabled

import Foundation

class RootAccountDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Root Account Is Disabled",
            description: "The root account has unlimited access to the system. Enabling it puts the system at risk. Administrators should use sudo instead. By default, root is disabled on macOS.",
            category: "CIS Benchmark",
            remediation: "Disable root with: sudo dsenableroot -d. To disable the root shell: dscl . -create /Users/root UserShell /usr/bin/false",
            severity: "High",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 5.6",
            mitigation: "Disabling root reduces the attack surface by requiring privilege escalation through sudo, which is auditable.",
            checkstatus: "",
            docID: 122,
            cisID: "5.6"
        )
    }

    override func check() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/dscl")
        task.arguments = [".", "-read", "/Users/root", "UserShell"]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = outputPipe
        task.standardError = errorPipe

        do {
            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if output.contains("/usr/bin/false") {
                status = "Root account is disabled (shell set to /usr/bin/false)."
                checkstatus = "Green"
            } else if output.contains("/bin/sh") || output.contains("/bin/zsh") || output.contains("/bin/bash") {
                status = "Root account has an active shell: \(output)."
                checkstatus = "Red"
            } else {
                status = "Root account shell status: \(output.isEmpty ? "unknown" : output)."
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking root account status"
        }
    }
}
