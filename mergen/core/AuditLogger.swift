//
//  AuditLogger.swift
//  mergen
//
//  Writes structured log entries to ~/Library/Logs/mergen/mergen-YYYY-MM-DD.log.
//  All writes are async on a background serial queue (never blocks the UI).
//

import Foundation

final class AuditLogger {

    static let shared = AuditLogger()

    private let logURL: URL
    private let queue  = DispatchQueue(label: "com.mergen.logger", qos: .background)

    private init() {


        let lib = FileManager.default
            .urls(for: .libraryDirectory, in: .userDomainMask).first!
        let dir = lib.appendingPathComponent("Logs/mergen", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let day = String(ISO8601DateFormatter().string(from: Date()).prefix(10))
        logURL = dir.appendingPathComponent("mergen-\(day).log")
    }

    // MARK: - Public API

    func logScanStart(category: String?) {
        write("SCAN_START  category=\"\(category ?? "All")\"")
    }

    func logCheckResult(_ v: Vulnerability) {
        let status = v.checkstatus ?? "unknown"
        let result = v.status.map { " result=\"\($0)\"" } ?? ""
        write("CHECK       cisID=\"\(v.cisID.isEmpty ? "-" : v.cisID)\" status=\(status) name=\"\(v.name)\"\(result)")
    }

    func logScanComplete(_ results: [Vulnerability]) {
        let pass     = results.filter { $0.checkstatus == "Green"  }.count
        let fail     = results.filter { $0.checkstatus == "Red"    }.count
        let warn     = results.filter { $0.checkstatus == "Yellow" }.count
        let advisory = results.filter { $0.checkstatus == "Blue"   }.count
        write("SCAN_DONE   total=\(results.count) pass=\(pass) fail=\(fail) warn=\(warn) advisory=\(advisory)")
    }

    func logFixStart(_ v: Vulnerability) {
        let priv = v.fixRequiresAdmin ? "admin" : "user"
        let cmd  = v.fixCommand ?? "—"
        write("FIX_START   cisID=\"\(v.cisID)\" name=\"\(v.name)\" priv=\(priv) cmd=\"\(cmd)\"")
    }

    func logFixResult(_ v: Vulnerability, success: Bool) {
        write("FIX_RESULT  cisID=\"\(v.cisID)\" name=\"\(v.name)\" success=\(success)")
    }

    func logAdminError(code: Int, message: String) {
        write("ADMIN_ERR   code=\(code) msg=\"\(message)\"")
    }

    /// URL of today's log file (for "Open in Finder" / "Reveal" actions).
    var logFileURL: URL { logURL }

    /// Returns the last `limit` log lines (most recent last).
    func recentLines(limit: Int = 600) -> [String] {
        guard let raw = try? String(contentsOf: logURL, encoding: .utf8) else { return [] }
        let lines = raw.components(separatedBy: "\n").filter { !$0.isEmpty }
        return Array(lines.suffix(limit))
    }

    // MARK: - Private

    private func write(_ body: String) {
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let line = "[\(stamp.string(from: Date()))] \(body)\n"
        queue.async {
            guard let data = line.data(using: .utf8) else { return }
            if FileManager.default.fileExists(atPath: self.logURL.path),
               let fh = try? FileHandle(forWritingTo: self.logURL) {
                fh.seekToEndOfFile()
                fh.write(data)
                fh.closeFile()
            } else {
                try? data.write(to: self.logURL, options: .atomic)
            }
        }
    }
}
