//
//  SleepEnabledAppleSiliconCheck.swift
//  mergen
//
//  CIS 2.10.1.2 - Ensure Sleep and Display Sleep Is Enabled on Apple Silicon Devices

import Foundation

class SleepEnabledAppleSiliconCheck: Vulnerability {
    init() {
        super.init(
            name: "Sleep ≤ 15 min & Display Sleep ≤ 10 min (Apple Silicon)",
            description: "MacBooks with Apple Silicon should sleep after ≤ 15 minutes of inactivity and display sleep after ≤ 10 minutes. This limits exposure when the device is unattended.",
            category: "CIS Benchmark",
            remediation: "Run: sudo pmset -a sleep 15 && sudo pmset -a displaysleep 10. This only applies to Apple Silicon MacBooks.",
            severity: "Medium",
            documentation: "CIS Apple macOS 26 Tahoe Benchmark v1.0.0 - Recommendation 2.10.1.2",
            mitigation: "Automatic sleep prevents unauthorized access to an unattended unlocked machine.",
            checkstatus: "",
            docID: 111,
            cisID: "2.10.1.2"
        )
    }

    override func check() {
        // First check if this is a MacBook with Apple Silicon
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

            // If it's an Intel Mac, this check doesn't apply
            if cpuOutput.contains("Intel") {
                status = "Not applicable — this check is for Apple Silicon Macs only."
                checkstatus = "Green"
                return
            }

            // Check sleep value
            let pmsetTask = Process()
            pmsetTask.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
            pmsetTask.arguments = ["-b", "-g"]

            let pmsetPipe = Pipe()
            pmsetTask.standardOutput = pmsetPipe
            pmsetTask.standardError = Pipe()

            try pmsetTask.run()
            pmsetTask.waitUntilExit()

            let pmsetOutput = String(data: pmsetPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

            var sleepOk = false
            var displaySleepOk = false

            for line in pmsetOutput.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("sleep") {
                    let parts = trimmed.components(separatedBy: .whitespaces)
                    if let val = parts.dropFirst().first.flatMap({ Int($0) }), val <= 15 {
                        sleepOk = true
                    }
                } else if trimmed.hasPrefix("displaysleep") {
                    let parts = trimmed.components(separatedBy: .whitespaces)
                    if let val = parts.dropFirst().first.flatMap({ Int($0) }), val <= 10 {
                        displaySleepOk = true
                    }
                }
            }

            if sleepOk && displaySleepOk {
                status = "Sleep and display sleep are configured correctly (≤ 15 min / ≤ 10 min)."
                checkstatus = "Green"
            } else {
                status = "Sleep or display sleep exceeds recommended thresholds (sleep ≤ 15 min, display sleep ≤ 10 min)."
                checkstatus = "Red"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            self.error = e
            checkstatus = "Yellow"
            status = "Error checking sleep settings"
        }
    }
}
