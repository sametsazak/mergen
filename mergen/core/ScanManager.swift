//
//  ScanManager.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import Combine

class ScanManager: ObservableObject {
    @Published var scanResults: [Vulnerability] = []
    @Published var progress: Double = 0
    @Published var scanning: Bool = false
    @Published var fixingIDs:     Set<UUID>  = []
    @Published var fixResults:    [UUID: Bool] = [:]   // true = check passed after fix
    @Published var fixCancelled:  Set<UUID>  = []      // user dismissed password dialog
    private var totalModules: Int = 0
    
    func startScan(category: String?) {
        scanning = true
        AuditLogger.shared.logScanStart(category: category)

        DispatchQueue.global(qos: .userInitiated).async {
            let scanner = Scanner()
            if let category = category {
                scanner.loadModules(category: category)
            } else {
                scanner.loadModules()
            }
            self.totalModules = scanner.moduleCount
            var completedModules = 0

            scanner.modules.forEach { module in
                let timeout: DispatchTimeInterval = .seconds(15)

                let semaphore = DispatchSemaphore(value: 0)

                let taskQueue = DispatchQueue(label: "com.sametsazak.mergen", qos: .userInteractive)
                taskQueue.async {
                    module.check()
                    semaphore.signal()
                }

                let result = semaphore.wait(timeout: DispatchTime.now() + timeout)

                if result == .timedOut {
                    module.checkstatus = "Yellow"
                    module.status = "Check timed out"
                }

                AuditLogger.shared.logCheckResult(module)

                DispatchQueue.main.async {
                    self.scanResults.append(module)
                    completedModules += 1
                    self.progress = Double(completedModules) / Double(self.totalModules)

                    if self.progress >= 0.9999 {
                        self.scanning = false
                        AuditLogger.shared.logScanComplete(self.scanResults)
                    }
                }
            }
        }
    }


    func resetScan() {
        scanning = false
        progress = 0.0
        scanResults = []
        fixingIDs    = []
        fixResults   = [:]
        fixCancelled = []
    }

    // MARK: - Auto-Remediation

    /// Applies the fix for a single vulnerability, then re-runs its check.
    /// Success is determined by whether the check passes after the fix, not by exit code.
    func applyFix(for vulnerability: Vulnerability) {
        guard vulnerability.isAutoFixable else { return }
        let id = vulnerability.id
        fixingIDs.insert(id)
        AuditLogger.shared.logFixStart(vulnerability)

        DispatchQueue.global(qos: .userInitiated).async {
            let cmd    = vulnerability.fixCommand!
            let result: FixResult
            if vulnerability.fixRequiresAdmin {
                result = FixManager.runAdminCommand(cmd)
            } else {
                result = FixManager.runUserCommand(cmd)
            }

            // Re-run the check unless the user cancelled the password dialog.
            if case .cancelled = result {
                AuditLogger.shared.logFixResult(vulnerability, success: false)
                DispatchQueue.main.async {
                    self.fixingIDs.remove(id)
                    self.fixCancelled.insert(id)
                    self.objectWillChange.send()
                }
                return
            }

            vulnerability.check()
            let success = vulnerability.checkstatus == "Green"
            AuditLogger.shared.logFixResult(vulnerability, success: success)

            DispatchQueue.main.async {
                self.fixingIDs.remove(id)
                self.fixResults[id] = success
                self.objectWillChange.send()
            }
        }
    }

    /// Applies fixes for a list of vulnerabilities.
    /// User-level fixes run one at a time (no password needed).
    /// Admin fixes are batched into ONE password dialog, joined with `;` so a
    /// single failing command doesn't block the rest. Real success is determined
    /// by re-running each check after the batch completes.
    func fixAll(_ vulnerabilities: [Vulnerability]) {
        let fixable    = vulnerabilities.filter { $0.isAutoFixable }
        let userFixes  = fixable.filter { !$0.fixRequiresAdmin }
        let adminFixes = fixable.filter {  $0.fixRequiresAdmin }
        guard !fixable.isEmpty else { return }

        fixingIDs.formUnion(fixable.map { $0.id })
        for v in fixable { AuditLogger.shared.logFixStart(v) }

        DispatchQueue.global(qos: .userInitiated).async {

            // ── User-level fixes (no password) ──────────────────────────────
            for v in userFixes {
                _ = FixManager.runUserCommand(v.fixCommand!)
                v.check()
                let success = v.checkstatus == "Green"
                AuditLogger.shared.logFixResult(v, success: success)
                DispatchQueue.main.async {
                    self.fixingIDs.remove(v.id)
                    self.fixResults[v.id] = success
                    self.objectWillChange.send()
                }
            }

            // ── Admin fixes — ONE password prompt ────────────────────────────
            // Join with `;` (not `&&`) so each command runs independently.
            // FixManager wraps the whole thing in `bash -c '...; exit 0'` so
            // the AppleScript call itself never fails due to individual commands.
            if !adminFixes.isEmpty {
                let combined = adminFixes.compactMap { $0.fixCommand }
                                         .joined(separator: " ; ")
                let result = FixManager.runAdminCommand(combined)

                if case .cancelled = result {
                    // User dismissed the dialog — mark all admin fixes as cancelled.
                    for v in adminFixes {
                        AuditLogger.shared.logFixResult(v, success: false)
                        DispatchQueue.main.async {
                            self.fixingIDs.remove(v.id)
                            self.fixCancelled.insert(v.id)
                            self.objectWillChange.send()
                        }
                    }
                    return
                }

                // Script ran — re-check each vulnerability to determine real outcome.
                for v in adminFixes {
                    v.check()
                    let success = v.checkstatus == "Green"
                    AuditLogger.shared.logFixResult(v, success: success)
                    DispatchQueue.main.async {
                        self.fixingIDs.remove(v.id)
                        self.fixResults[v.id] = success
                        self.objectWillChange.send()
                    }
                }
            }
        }
    }
}


