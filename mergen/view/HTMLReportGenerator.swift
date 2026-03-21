//
//  HTMLReportGenerator.swift
//  mergen
//

import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct HTMLReportGenerator {

    let scanResults: [Vulnerability]

    init(scanResults: [Vulnerability]) {
        self.scanResults = scanResults
    }

    // MARK: - Public

    func generateHTMLReport() -> String {
        let automated   = scanResults.filter { !$0.isManual && $0.checkstatus != "Blue" }
        let passCount   = automated.filter { $0.checkstatus == "Green" }.count
        let failCount   = scanResults.filter { $0.checkstatus == "Red" }.count
        let warnCount   = scanResults.filter { $0.checkstatus == "Yellow" }.count
        let advisoryCount = scanResults.filter { $0.checkstatus == "Blue" }.count
        let total       = automated.count
        let score       = total > 0 ? Double(passCount) / Double(total) : 0.0
        let scoreInt    = Int(score * 100)
        let scoreLabel  = score >= 0.8 ? "GOOD" : score >= 0.5 ? "FAIR" : "AT RISK"
        let scoreColor  = score >= 0.8 ? "#21d49c" : score >= 0.5 ? "#f7a13a" : "#f25c5c"

        // Score ring SVG values
        let circumference = 314.159
        let dashOn  = String(format: "%.2f", score * circumference)
        let dashOff = String(format: "%.2f", circumference - score * circumference)

        // System info
        let host       = Host.current().localizedName ?? "Unknown"
        let osVersion  = ProcessInfo.processInfo.operatingSystemVersionString
        let dateStr    = Self.formattedDate()
        let checkCount = scanResults.count

        // Group by CIS section
        let sections = cisSections()
        let sectionBars = buildSectionBars(sections: sections)
        let resultBlocks = buildResultBlocks(sections: sections)
        let remediationCards = buildRemediationCards()

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Mergen — Security Audit Report</title>
        <style>
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

        :root{
          --bg:#120828;--bg2:#1d1245;--card:rgba(255,255,255,.055);
          --border:rgba(255,255,255,.10);--text:#fff;--muted:rgba(255,255,255,.55);
          --faint:rgba(255,255,255,.28);
          --green:#21d49c;--red:#f25c5c;--amber:#f7a13a;--blue:#4590f3;--lav:#a685ff;
          --r:12px;
        }

        body{
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
          background:linear-gradient(135deg,#120828 0%,#1d1245 45%,#2e1f58 75%,#3c2870 100%);
          min-height:100vh;color:var(--text);-webkit-font-smoothing:antialiased;
        }

        .cover{
          min-height:100vh;display:flex;flex-direction:column;
          align-items:center;justify-content:center;text-align:center;
          padding:60px 40px;
          background:linear-gradient(160deg,#0d0520 0%,#160d38 50%,#221a4a 100%);
          page-break-after:always;position:relative;overflow:hidden;
        }
        .cover-glow{
          position:absolute;width:700px;height:700px;border-radius:50%;
          background:radial-gradient(circle,rgba(166,133,255,.18) 0%,transparent 68%);
          top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none;
        }
        .cover-logo{
          width:88px;height:88px;border-radius:22px;margin:0 auto 26px;
          background:linear-gradient(135deg,#a685ff,#5520cc);
          display:flex;align-items:center;justify-content:center;
          font-size:42px;box-shadow:0 0 48px rgba(166,133,255,.45);
          position:relative;z-index:1;
        }
        .cover-title{font-size:38px;font-weight:700;letter-spacing:-.5px;margin-bottom:8px;position:relative;z-index:1;}
        .cover-sub{font-size:14px;color:var(--muted);margin-bottom:36px;position:relative;z-index:1;}
        .cover-score{margin-bottom:36px;position:relative;z-index:1;}
        .cover-meta{
          display:flex;gap:28px;flex-wrap:wrap;justify-content:center;
          position:relative;z-index:1;
        }
        .meta-item{display:flex;flex-direction:column;align-items:center;gap:4px;}
        .meta-label{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;color:var(--faint);}
        .meta-val{font-size:13px;color:var(--muted);}

        .content{max-width:920px;margin:0 auto;padding:44px 40px;}

        .section-heading{
          display:flex;align-items:center;gap:10px;
          margin:36px 0 18px;padding-bottom:10px;
          border-bottom:1px solid var(--border);
        }
        .section-heading:first-child{margin-top:0;}
        .section-heading h2{font-size:17px;font-weight:600;}
        .dot{width:8px;height:8px;border-radius:50%;background:var(--lav);box-shadow:0 0 8px var(--lav);flex-shrink:0;}
        .sub{font-size:13px;color:var(--muted);margin:-10px 0 18px;}

        .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}
        .stat-card{
          background:var(--card);border:1px solid var(--border);border-radius:var(--r);
          padding:20px 14px;text-align:center;position:relative;overflow:hidden;
        }
        .stat-card::before{
          content:'';position:absolute;top:0;left:0;right:0;height:3px;
          border-radius:var(--r) var(--r) 0 0;
        }
        .stat-card.green::before{background:var(--green);}
        .stat-card.red::before{background:var(--red);}
        .stat-card.amber::before{background:var(--amber);}
        .stat-card.blue::before{background:var(--blue);}
        .stat-num{font-size:34px;font-weight:700;line-height:1;margin-bottom:6px;}
        .stat-card.green .stat-num{color:var(--green);}
        .stat-card.red   .stat-num{color:var(--red);}
        .stat-card.amber .stat-num{color:var(--amber);}
        .stat-card.blue  .stat-num{color:var(--blue);}
        .stat-lbl{font-size:11px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.7px;}

        .bars-card{
          background:var(--card);border:1px solid var(--border);border-radius:var(--r);
          padding:20px;margin-bottom:32px;
        }
        .bars-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;}
        .bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px;}
        .bar-row:last-child{margin-bottom:0;}
        .bar-label{font-size:11px;color:var(--muted);font-family:'Menlo','SF Mono',monospace;width:200px;flex-shrink:0;}
        .bar-track{flex:1;height:7px;background:rgba(255,255,255,.08);border-radius:4px;overflow:hidden;}
        .bar-fill{height:100%;border-radius:4px;}
        .bar-count{font-size:11px;color:var(--faint);font-family:'Menlo','SF Mono',monospace;width:38px;text-align:right;flex-shrink:0;}

        .result-block{margin-bottom:32px;page-break-inside:avoid;}
        .section-label{
          font-size:12px;font-weight:600;color:var(--muted);
          text-transform:uppercase;letter-spacing:.9px;
          margin-bottom:10px;padding:7px 12px;
          background:rgba(255,255,255,.04);border-radius:6px;
          border-left:3px solid var(--lav);
        }

        table{width:100%;border-collapse:collapse;background:var(--card);
          border:1px solid var(--border);border-radius:var(--r);overflow:hidden;font-size:13px;}
        thead th{
          padding:10px 13px;text-align:left;font-size:10px;font-weight:600;
          color:var(--muted);text-transform:uppercase;letter-spacing:.7px;
          background:rgba(255,255,255,.04);border-bottom:1px solid var(--border);
        }
        tbody tr{border-bottom:1px solid rgba(255,255,255,.05);}
        tbody tr:last-child{border-bottom:none;}
        td{padding:9px 13px;vertical-align:middle;}
        .cis{
          font-family:'Menlo','SF Mono',monospace;font-size:10px;color:var(--muted);
          background:rgba(255,255,255,.07);padding:2px 6px;border-radius:4px;white-space:nowrap;
        }
        .check-name{font-weight:500;font-size:13px;}
        .detail{font-size:11px;color:var(--muted);margin-top:3px;}

        .badge{
          display:inline-flex;align-items:center;padding:3px 9px;
          border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap;
        }
        .badge.pass{color:var(--green);background:rgba(33,212,156,.12);}
        .badge.fail{color:var(--red);background:rgba(242,92,92,.12);}
        .badge.warn{color:var(--amber);background:rgba(247,161,58,.12);}
        .badge.info{color:var(--blue);background:rgba(69,144,243,.12);}

        .sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;text-transform:uppercase;letter-spacing:.4px;}
        .sev.critical{color:var(--red);background:rgba(242,92,92,.15);}
        .sev.high{color:var(--amber);background:rgba(247,161,58,.15);}
        .sev.medium{color:#e0c840;background:rgba(224,200,64,.15);}
        .sev.low{color:var(--blue);background:rgba(69,144,243,.15);}

        .rem-card{
          margin-bottom:14px;padding:16px;
          background:var(--card);border:1px solid var(--border);
          border-left:3px solid var(--red);border-radius:0 var(--r) var(--r) 0;
          page-break-inside:avoid;
        }
        .rem-head{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
        .rem-name{font-size:13px;font-weight:600;flex:1;}
        .finding{font-size:12px;color:var(--muted);margin-bottom:8px;}
        pre.rem-body{
          font-family:'Menlo','SF Mono',monospace;font-size:11px;
          color:rgba(255,255,255,.65);line-height:1.6;white-space:pre-wrap;
          background:rgba(0,0,0,.25);padding:10px 12px;border-radius:8px;
        }

        .footer{
          text-align:center;padding:22px 40px;color:var(--faint);font-size:11px;
          border-top:1px solid var(--border);margin-top:20px;
        }

        @media print{
          body{background:#120828 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
          .cover{page-break-after:always;}
          .result-block,.rem-card{page-break-inside:avoid;}
          @page{margin:0;}
        }
        </style>
        </head>
        <body>

        <!-- Cover -->
        <div class="cover">
          <div class="cover-glow"></div>
          <div class="cover-logo">🛡</div>
          <h1 class="cover-title">Security Audit Report</h1>
          <p class="cover-sub">Generated by Mergen · CIS Apple macOS 26 Tahoe Benchmark v1.0.0</p>
          <div class="cover-score">
            <svg width="140" height="140" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.10)" stroke-width="10"/>
              <circle cx="60" cy="60" r="50" fill="none"
                stroke="\(scoreColor)" stroke-width="10"
                stroke-dasharray="\(dashOn) \(dashOff)"
                stroke-linecap="round"
                transform="rotate(-90 60 60)"/>
              <text x="60" y="55" text-anchor="middle"
                fill="\(scoreColor)" font-size="22" font-weight="700"
                font-family="-apple-system,BlinkMacSystemFont,sans-serif">\(scoreInt)%</text>
              <text x="60" y="71" text-anchor="middle"
                fill="rgba(255,255,255,0.45)" font-size="9" font-weight="600"
                font-family="-apple-system,BlinkMacSystemFont,sans-serif"
                letter-spacing="1">\(scoreLabel)</text>
            </svg>
          </div>
          <div class="cover-meta">
            <div class="meta-item"><div class="meta-label">HOST</div><div class="meta-val">\(escapeHTML(host))</div></div>
            <div class="meta-item"><div class="meta-label">SYSTEM</div><div class="meta-val">\(escapeHTML(osVersion))</div></div>
            <div class="meta-item"><div class="meta-label">DATE</div><div class="meta-val">\(dateStr)</div></div>
            <div class="meta-item"><div class="meta-label">CHECKS</div><div class="meta-val">\(checkCount)</div></div>
          </div>
        </div>

        <!-- Content -->
        <div class="content">

          <div class="section-heading"><div class="dot"></div><h2>Executive Summary</h2></div>
          <div class="stat-grid">
            <div class="stat-card green"><div class="stat-num">\(passCount)</div><div class="stat-lbl">Passed</div></div>
            <div class="stat-card red"><div class="stat-num">\(failCount)</div><div class="stat-lbl">Failed</div></div>
            <div class="stat-card amber"><div class="stat-num">\(warnCount)</div><div class="stat-lbl">Warnings</div></div>
            <div class="stat-card blue"><div class="stat-num">\(advisoryCount)</div><div class="stat-lbl">Advisory</div></div>
          </div>

          <div class="bars-card">
            <div class="bars-title">Pass Rate by Section</div>
            \(sectionBars)
          </div>

          <div class="section-heading"><div class="dot"></div><h2>Check Results</h2></div>
          \(resultBlocks)

          <div class="section-heading"><div class="dot"></div><h2>Remediation Steps</h2></div>
          \(remediationCards)

        </div>

        <div class="footer">Generated by Mergen · CIS Apple macOS 26 Tahoe Benchmark v1.0.0 · \(dateStr)</div>
        </body>
        </html>
        """
    }

    // MARK: - Helpers

    private func cisSections() -> [(label: String, items: [Vulnerability])] {
        let sectionDefs: [(prefix: String, label: String)] = [
            ("1", "§1 · Updates & Patches"),
            ("2", "§2 · System Settings"),
            ("3", "§3 · Logging & Auditing"),
            ("4", "§4 · Network"),
            ("5", "§5 · Auth & Authorization"),
            ("6", "§6 · User Interface"),
        ]

        var sections: [(label: String, items: [Vulnerability])] = []
        var used = Set<String>()

        for (prefix, label) in sectionDefs {
            let items = scanResults.filter { v in
                let first = v.cisID.split(separator: ".").first.map(String.init) ?? ""
                return first == prefix
            }
            if !items.isEmpty {
                sections.append((label, items))
                items.forEach { used.insert($0.id.uuidString) }
            }
        }

        let other = scanResults.filter { !used.contains($0.id.uuidString) }
        if !other.isEmpty {
            sections.append(("Other", other))
        }

        return sections
    }

    private func buildSectionBars(sections: [(label: String, items: [Vulnerability])]) -> String {
        sections.map { sec in
            let automated = sec.items.filter { !$0.isManual && $0.checkstatus != "Blue" }
            let pass      = automated.filter { $0.checkstatus == "Green" }.count
            let total     = automated.count
            let pct       = total > 0 ? Int(Double(pass) / Double(total) * 100) : 0
            let color     = pct >= 80 ? "#21d49c" : pct >= 50 ? "#f7a13a" : "#f25c5c"
            return """
            <div class="bar-row">
              <div class="bar-label">\(escapeHTML(sec.label))</div>
              <div class="bar-track"><div class="bar-fill" style="width:\(pct)%;background:\(color)"></div></div>
              <div class="bar-count">\(pass)/\(total)</div>
            </div>
            """
        }.joined()
    }

    private func buildResultBlocks(sections: [(label: String, items: [Vulnerability])]) -> String {
        sections.map { sec in
            let rows = sec.items.map { v -> String in
                let cisCell = v.cisID.isEmpty ? "<td>—</td>" : "<td><span class=\"cis\">\(escapeHTML(v.cisID))</span></td>"
                let detail  = v.status.map { "<div class=\"detail\">\(escapeHTML($0))</div>" } ?? ""
                let sevClass = severityClass(v.severity)
                let badgeClass: String
                let badgeLabel: String
                switch v.checkstatus {
                case "Green":  badgeClass = "pass"; badgeLabel = "Passed"
                case "Red":    badgeClass = "fail"; badgeLabel = "Failed"
                case "Yellow": badgeClass = "warn"; badgeLabel = "Warning"
                case "Blue":   badgeClass = "info"; badgeLabel = "Advisory"
                default:       badgeClass = "info"; badgeLabel = v.checkstatus ?? "Unknown"
                }
                return """
                <tr>
                  \(cisCell)
                  <td><div class="check-name">\(escapeHTML(v.name))</div>\(detail)</td>
                  <td><span class="sev \(sevClass)">\(escapeHTML(v.severity))</span></td>
                  <td><span class="badge \(badgeClass)">\(badgeLabel)</span></td>
                </tr>
                """
            }.joined()

            return """
            <div class="result-block">
              <div class="section-label">\(escapeHTML(sec.label))</div>
              <table>
                <thead>
                  <tr>
                    <th style="width:80px">CIS ID</th>
                    <th>Check</th>
                    <th style="width:88px">Severity</th>
                    <th style="width:96px">Result</th>
                  </tr>
                </thead>
                <tbody>\(rows)</tbody>
              </table>
            </div>
            """
        }.joined()
    }

    private func buildRemediationCards() -> String {
        let needsAction = scanResults.filter {
            $0.checkstatus == "Red" || $0.checkstatus == "Yellow"
        }.sorted {
            severityRank($0.severity) > severityRank($1.severity)
        }

        if needsAction.isEmpty {
            return "<p class=\"sub\">No remediation required — all checks passed.</p>"
        }

        let countStr = "\(needsAction.count) check\(needsAction.count == 1 ? "" : "s")"
        let intro = "<p class=\"sub\">The following \(countStr) require attention, ordered by severity.</p>"

        let cards = needsAction.map { v -> String in
            let borderColor = v.checkstatus == "Red" ? "#f25c5c" : "#f7a13a"
            let cisSpan = v.cisID.isEmpty ? "" : "<span class=\"cis\">\(escapeHTML(v.cisID))</span>"
            let finding = v.status.map { escapeHTML($0) } ?? "Review this check manually."
            let sevClass = severityClass(v.severity)
            return """
            <div class="rem-card" style="border-left-color:\(borderColor)">
              <div class="rem-head">
                \(cisSpan)
                <span class="rem-name">\(escapeHTML(v.name))</span>
                <span class="sev \(sevClass)">\(escapeHTML(v.severity))</span>
              </div>
              <p class="finding">Finding: \(finding)</p>
              <pre class="rem-body">\(escapeHTML(v.remediation))</pre>
            </div>
            """
        }.joined()

        return intro + cards
    }

    private func severityClass(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "critical"
        case "high":     return "high"
        case "medium":   return "medium"
        default:         return "low"
        }
    }

    private func severityRank(_ severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": return 4
        case "high":     return 3
        case "medium":   return 2
        default:         return 1
        }
    }

    private func escapeHTML(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
    }

    private static func formattedDate() -> String {
        let f = DateFormatter()
        f.dateStyle = .long
        f.timeStyle = .short
        return f.string(from: Date())
    }
}

// MARK: - File Utils

struct FileUtils {
    static func saveHTMLStringToFile(_ htmlString: String) {
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "MergenReport.html"
        savePanel.allowedContentTypes = [UTType.html]

        if savePanel.runModal() == .OK, let url = savePanel.url {
            do {
                try htmlString.write(to: url, atomically: true, encoding: .utf8)
                print("HTML file saved to \(url)")
            } catch {
                print("Error saving HTML file: \(error)")
            }
        }
    }
}
