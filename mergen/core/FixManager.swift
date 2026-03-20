//
//  FixManager.swift
//  mergen
//
//  Execution engine for auto-remediation.
//
//  Design notes:
//  • User-level fixes  → Process(/bin/bash -c). Exit code 0 = ran cleanly.
//  • Admin-level fixes → NSAppleScript "do shell script ... with administrator privileges".
//    The script is wrapped in "bash -c '...; exit 0'" so that individual command
//    failures (e.g. launchctl stop on an already-stopped service) don't abort the
//    whole batch. The only hard failure is AppleScript error -128 (user cancelled).
//    Real success is determined by re-running the check, not by the shell exit code.
//

import Foundation
import AppKit

enum FixResult {
    case success          // command ran; check will verify outcome
    case cancelled        // user dismissed the password dialog
    case scriptError(String) // AppleScript or process failed to launch
}

enum FixManager {

    // MARK: - User-level (no password)

    /// Runs a shell command as the current user. Returns `.success` on exit 0.
    static func runUserCommand(_ cmd: String) -> FixResult {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments     = ["-c", cmd]
        proc.standardOutput = Pipe()
        proc.standardError  = Pipe()
        do {
            try proc.run()
            proc.waitUntilExit()
            if proc.terminationStatus == 0 {
                return .success
            } else {
                return .scriptError("exit \(proc.terminationStatus)")
            }
        } catch {
            return .scriptError(error.localizedDescription)
        }
    }

    // MARK: - Admin-level (one password dialog)

    /// Runs a shell command with administrator privileges via NSAppleScript.
    ///
    /// The command is wrapped in `bash -c '...; exit 0'` so individual failures
    /// inside the script do not cause the whole AppleScript call to fail.
    /// Only AppleScript error -128 (user cancelled) returns `.cancelled`.
    /// Any other AppleScript error is logged but treated as `.success` — the
    /// caller must re-run the check to determine whether the fix actually worked.
    static func runAdminCommand(_ cmd: String) -> FixResult {
        // Wrap in bash and force exit 0 so intermediate failures don't cascade.
        // Shell-escape single quotes inside cmd, then wrap in single-quoted bash arg.
        let shellCmd    = cmd.replacingOccurrences(of: "'", with: "'\\''")
        let bashWrapped = "bash -c '\(shellCmd); exit 0'"

        // Escape for AppleScript double-quoted string.
        let escaped = bashWrapped
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")

        let source = "do shell script \"\(escaped)\" with administrator privileges"
        guard let script = NSAppleScript(source: source) else {
            return .scriptError("NSAppleScript could not be initialised")
        }

        var errorDict: NSDictionary?
        script.executeAndReturnError(&errorDict)

        guard let err = errorDict else { return .success }

        let code    = (err[NSAppleScript.errorNumber]  as? Int)    ?? 0
        let message = (err[NSAppleScript.errorMessage] as? String) ?? "unknown"

        // -128 = user clicked Cancel in the password dialog.
        if code == -128 { return .cancelled }

        // Any other code: the script itself errored (unusual with our bash wrapper).
        // Log it and return success anyway — the re-check decides real outcome.
        AuditLogger.shared.logAdminError(code: code, message: message)
        return .success
    }
}
