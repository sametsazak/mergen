//
//  LogViewerSheet.swift
//  mergen
//
//  In-app viewer for ~/Library/Logs/mergen/mergen-YYYY-MM-DD.log.
//

import SwiftUI
import AppKit

struct LogViewerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var lines:       [String] = []
    @State private var filter:      LogFilter = .all
    @State private var searchText   = ""

    enum LogFilter: String, CaseIterable {
        case all    = "All"
        case scan   = "Scan"
        case check  = "Check"
        case fix    = "Fix"
        case errors = "Errors"

        var keyword: String? {
            switch self {
            case .all:    return nil
            case .scan:   return "SCAN"
            case .check:  return "CHECK"
            case .fix:    return "FIX"
            case .errors: return "success=false"
            }
        }

        var color: Color {
            switch self {
            case .all:    return .primary
            case .scan:   return .accentColor
            case .check:  return .secondary
            case .fix:    return .orange
            case .errors: return .red
            }
        }
    }

    private var filtered: [String] {
        var out = lines
        if let kw = filter.keyword {
            out = out.filter { $0.contains(kw) }
        }
        if !searchText.isEmpty {
            out = out.filter { $0.localizedCaseInsensitiveContains(searchText) }
        }
        return out
    }

    var body: some View {
        VStack(spacing: 0) {

            // ── Header ───────────────────────────────────────────────────────
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Audit Log")
                        .font(.system(size: 16, weight: .bold))
                    Text(AuditLogger.shared.logFileURL.path)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting(
                        [AuditLogger.shared.logFileURL]
                    )
                } label: {
                    Label("Reveal", systemImage: "folder")
                        .font(.system(size: 11))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button {
                    let all = lines.joined(separator: "\n")
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(all, forType: .string)
                } label: {
                    Label("Copy All", systemImage: "doc.on.doc")
                        .font(.system(size: 11))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 18))
                        .foregroundColor(.secondary.opacity(0.6))
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            // ── Search + filter bar ──────────────────────────────────────────
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                    .font(.system(size: 12))
                TextField("Search log…", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                    }.buttonStyle(.plain)
                }

                Divider().frame(height: 16)

                ForEach(LogFilter.allCases, id: \.rawValue) { f in
                    Button(f.rawValue) { filter = f }
                        .buttonStyle(.plain)
                        .font(.system(size: 11, weight: filter == f ? .semibold : .regular))
                        .foregroundColor(filter == f ? f.color : .secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(
                            RoundedRectangle(cornerRadius: 5)
                                .fill(filter == f ? f.color.opacity(0.12) : Color.clear)
                        )
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(Color.primary.opacity(0.03))

            Divider()

            // ── Log lines ───────────────────────────────────────────────────
            if filtered.isEmpty {
                VStack(spacing: 10) {
                    Spacer()
                    Image(systemName: "doc.text")
                        .font(.system(size: 36))
                        .foregroundColor(.secondary.opacity(0.3))
                    Text(lines.isEmpty ? "No log entries yet. Run a scan to start logging." : "No entries match your filter.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(filtered.enumerated()), id: \.offset) { idx, line in
                                LogLine(text: line)
                                    .id(idx)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                    }
                    .onAppear {
                        proxy.scrollTo(filtered.count - 1, anchor: .bottom)
                    }
                }
            }

            Divider()

            // ── Footer ──────────────────────────────────────────────────────
            HStack {
                Text("\(filtered.count) of \(lines.count) entries")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                Spacer()
                Button {
                    loadLines()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                        .font(.system(size: 11))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button("Close") { dismiss() }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
            }
            .padding(12)
        }
        .frame(width: 780, height: 520)
        .onAppear { loadLines() }
    }

    private func loadLines() {
        lines = AuditLogger.shared.recentLines(limit: 600)
    }
}

// MARK: - Log Line View

private struct LogLine: View {
    let text: String

    private var lineColor: Color {
        if text.contains("FIX_RESULT") && text.contains("success=false") { return .red }
        if text.contains("FIX_RESULT") && text.contains("success=true")  { return .green }
        if text.contains("FIX_START")  { return .orange }
        if text.contains("SCAN_DONE")  { return .accentColor }
        if text.contains("SCAN_START") { return .accentColor }
        if text.contains("CHECK") {
            if text.contains("status=Red")    { return .red.opacity(0.8) }
            if text.contains("status=Yellow") { return .orange.opacity(0.8) }
            if text.contains("status=Green")  { return .green.opacity(0.8) }
        }
        return .primary
    }

    private var timestamp: String {
        guard text.hasPrefix("["), let end = text.firstIndex(of: "]") else { return "" }
        return String(text[text.index(after: text.startIndex)..<end])
    }

    private var body_: String {
        guard let end = text.firstIndex(of: "]") else { return text }
        return String(text[text.index(end, offsetBy: 2)...])
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(timestamp)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 140, alignment: .leading)
                .lineLimit(1)

            Text(body_)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(lineColor)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
    }
}
