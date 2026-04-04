//
//  ShellScriptReportGenerator.swift
//  mergen
//
//  Generates a shell (.sh) remediation script from failed scan results.
//  User-level fixes are grouped separately from admin (sudo) fixes.
//  Checks with no auto-fix command appear as commented manual instructions.
//

import Foundation

class ShellScriptReportGenerator {
    private let scanResults: [Vulnerability]

    init(scanResults: [Vulnerability]) {
        self.scanResults = scanResults
    }

    func generateScript() -> String {
        let failed   = scanResults.filter { $0.checkstatus == "Red" }
        let fixable  = failed.filter { $0.fixCommand != nil }
        let userFix  = fixable.filter { !$0.fixRequiresAdmin }.sorted { $0.cisID < $1.cisID }
        let adminFix = fixable.filter {  $0.fixRequiresAdmin }.sorted { $0.cisID < $1.cisID }
        // Manual = Red, no fixCommand, not an advisory/manual check
        let manual   = failed.filter { $0.fixCommand == nil && !$0.isManual }.sorted { $0.cisID < $1.cisID }

        let host = Host.current().localizedName ?? "unknown"
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let date = formatter.string(from: Date())

        var out = ""

        out += "#!/bin/bash\n"
        out += "# =================================================================\n"
        out += "# Mergen Security Remediation Script\n"
        out += "# Generated : \(date)\n"
        out += "# Host      : \(host)\n"
        out += "# Failed    : \(failed.count) checks\n"
        out += "# Auto-fix  : \(fixable.count) commands included\n"
        out += "# Manual    : \(manual.count) checks require manual review\n"
        out += "# =================================================================\n"
        out += "#\n"
        out += "# Review each command before running.\n"
        out += "# User-level section: run as your normal user.\n"
        out += "# Admin section     : run with sudo  (sudo bash <script>)\n"
        out += "# =================================================================\n\n"

        // ── User-level fixes ──────────────────────────────────────────────
        if !userFix.isEmpty {
            out += separator("USER-LEVEL FIXES  (no sudo required)")
            for v in userFix {
                out += comment(v)
                out += v.fixCommand! + "\n\n"
            }
        }

        // ── Admin fixes ───────────────────────────────────────────────────
        if !adminFix.isEmpty {
            out += separator("ADMIN FIXES  (requires sudo / run as root)")
            for v in adminFix {
                out += comment(v)
                out += v.fixCommand! + "\n\n"
            }
        }

        // ── Manual remediation ────────────────────────────────────────────
        if !manual.isEmpty {
            out += separator("MANUAL REMEDIATION  (no auto-fix available)")
            for v in manual {
                out += comment(v)
                for line in v.remediation.components(separatedBy: "\n") {
                    out += "#   \(line)\n"
                }
                out += "\n"
            }
        }

        if fixable.isEmpty && manual.isEmpty {
            out += "# Nothing to remediate — all checks passed.\n"
        }

        return out
    }

    // MARK: - Helpers

    private func separator(_ title: String) -> String {
        "# -----------------------------------------------------------------\n" +
        "# \(title)\n" +
        "# -----------------------------------------------------------------\n\n"
    }

    private func comment(_ v: Vulnerability) -> String {
        var s = "# [\(v.cisID.isEmpty ? "—" : v.cisID)] \(v.name)\n"
        if let desc = v.fixDescription {
            s += "# Effect: \(desc)\n"
        }
        return s
    }
}
