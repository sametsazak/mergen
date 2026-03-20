//
//  PowerNapDisabledCheck.swift
//  mergen
//
//  CIS 2.10.2 - Ensure Power Nap Is Disabled for Intel Macs

import Foundation

class PowerNapDisabledCheck: Vulnerability {
    init() {
        super.init(
            name: "Power Nap Is Disabled (Intel Macs)",
            description: "Power Nap allows the system to periodically connect to known networks while asleep, requiring FileVault to remain unlocked. This is a risk if the device is in an untrusted environment.",
            category: "CIS Benchmark",
            remediation: "Run: sudo pmset -a powernap 0. This only applies to Intel Macs.",
            severity: "Low",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.10.2",
            mitigation: "Disabling Power Nap mitigates the risk of an attacker remotely waking the system and gaining access.",
            checkstatus: "",
            docID: 112,
            cisID: "2.10.2"
        )
    }

    override func check() {
        // Only applies to Intel Macs
        let cpuTask = Process()
        cpuTask.executableURL = URL(fileURLWithPath: "/usr/sbin/sysctl")
        cpuTask.arguments = ["-n", "machdep.cpu.brand_string"]

        let cpuPipe = Pipe()
        cpuTask.standardOutput = cpuPipe
        cpuTask.standardError = Pipe()

        do {
            try cpuTask.run()
            cpuTask.waitUntilExit()
            let cpuOutput = String(data: cpuPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            if !cpuOutput.contains("Intel") {
                status = "Not applicable — this check is for Intel Macs only."
                checkstatus = "Green"
                return
            }

            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
            task.arguments = ["-g", "custom"]

            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = Pipe()

            try task.run()
            task.waitUntilExit()

            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            // Check if powernap is set to 1 anywhere
            let lines = output.components(separatedBy: "\n")
            let powerNapOn = lines.contains { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return trimmed.hasPrefix("powernap") && trimmed.hasSuffix("1")
            }

            if powerNapOn {
                status = "Power Nap is enabled."
                checkstatus = "Red"
            } else {
                status = "Power Nap is disabled."
                checkstatus = "Green"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking Power Nap status"
        }
    }
}
