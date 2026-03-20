//
//  ScanResultView.swift
//  mergen
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - Filter Types

enum StatusFilter: String, CaseIterable, Identifiable {
    case all      = "All"
    case failed   = "Failed"
    case passed   = "Passed"
    case warned   = "Warnings"
    case advisory = "Advisory"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .all:      return "circle.grid.3x3"
        case .failed:   return "xmark.circle.fill"
        case .passed:   return "checkmark.circle.fill"
        case .warned:   return "exclamationmark.triangle.fill"
        case .advisory: return "info.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .all:      return .primary
        case .failed:   return .red
        case .passed:   return .green
        case .warned:   return .orange
        case .advisory: return .blue
        }
    }
}

enum ResultSortOrder: String, CaseIterable {
    case cisID    = "CIS ID"
    case severity = "Severity"
    case name     = "Name"
    case status   = "Status"
}

// MARK: - Results List View

struct ResultsListView: View {
    @ObservedObject var scanManager: ScanManager
    let selectedCategory: String?
    @Binding var selectedVulnerability: Vulnerability?
    @Binding var searchText: String

    @State private var statusFilter: StatusFilter = .all
    @State private var severityFilter = "Any"
    @State private var sortOrder: ResultSortOrder = .cisID
    @State private var showFixSheet = false

    private let severities = ["Any", "Critical", "High", "Medium", "Low"]

    // MARK: Computed

    private var base: [Vulnerability] {
        selectedCategory == nil
            ? scanManager.scanResults
            : scanManager.scanResults.filter { $0.category == selectedCategory }
    }

    private var results: [Vulnerability] {
        var out = base

        if !searchText.isEmpty {
            let q = searchText
            out = out.filter {
                $0.name.localizedCaseInsensitiveContains(q) ||
                $0.description.localizedCaseInsensitiveContains(q) ||
                $0.cisID.localizedCaseInsensitiveContains(q) ||
                ($0.status ?? "").localizedCaseInsensitiveContains(q)
            }
        }

        switch statusFilter {
        case .failed:   out = out.filter { $0.checkstatus == "Red" }
        case .passed:   out = out.filter { $0.checkstatus == "Green" }
        case .warned:   out = out.filter { $0.checkstatus == "Yellow" }
        case .advisory: out = out.filter { $0.checkstatus == "Blue" || $0.isManual }
        case .all:      break
        }

        if severityFilter != "Any" {
            out = out.filter { $0.severity.lowercased() == severityFilter.lowercased() }
        }

        return out
    }

    private var grouped: [(section: String, items: [Vulnerability])] {
        let dict = Dictionary(grouping: results) { v -> String in
            guard !v.cisID.isEmpty else { return "Other" }
            switch v.cisID.split(separator: ".").first.map(String.init) ?? "" {
            case "1": return "1 · Updates & Patches"
            case "2": return "2 · System Settings"
            case "3": return "3 · Logging & Auditing"
            case "4": return "4 · Network"
            case "5": return "5 · Auth & Authorization"
            case "6": return "6 · User Interface"
            default:  return "Other"
            }
        }
        let order = [
            "1 · Updates & Patches",
            "2 · System Settings",
            "3 · Logging & Auditing",
            "4 · Network",
            "5 · Auth & Authorization",
            "6 · User Interface",
            "Other"
        ]
        return order.compactMap { key in
            guard let items = dict[key], !items.isEmpty else { return nil }
            return (section: key, items: sortedItems(items))
        }
    }

    private func sortedItems(_ items: [Vulnerability]) -> [Vulnerability] {
        let sevRank  = ["Critical": 0, "High": 1, "Medium": 2, "Low": 3]
        let statRank = ["Red": 0, "Yellow": 1, "Blue": 2, "Green": 3]
        switch sortOrder {
        case .cisID:
            return items.sorted {
                if $0.cisID.isEmpty && $1.cisID.isEmpty { return $0.name < $1.name }
                if $0.cisID.isEmpty { return false }
                if $1.cisID.isEmpty { return true }
                return $0.cisID.localizedStandardCompare($1.cisID) == .orderedAscending
            }
        case .severity:
            return items.sorted { (sevRank[$0.severity] ?? 99) < (sevRank[$1.severity] ?? 99) }
        case .name:
            return items.sorted { $0.name < $1.name }
        case .status:
            return items.sorted { (statRank[$0.checkstatus ?? ""] ?? 99) < (statRank[$1.checkstatus ?? ""] ?? 99) }
        }
    }

    // Counts for filter pills (always show real totals from base, not filtered)
    private var failedCount:   Int { base.filter { $0.checkstatus == "Red" }.count }
    private var passedCount:   Int { base.filter { $0.checkstatus == "Green" }.count }
    private var warnedCount:   Int { base.filter { $0.checkstatus == "Yellow" }.count }
    private var advisoryCount: Int { base.filter { $0.checkstatus == "Blue" || $0.isManual }.count }
    private var fixableCount:  Int { base.filter { $0.isAutoFixable }.count }
    private var hasFilters: Bool { statusFilter != .all || severityFilter != "Any" || !searchText.isEmpty }

    // MARK: Body

    var body: some View {
        Group {
            if scanManager.scanResults.isEmpty && !scanManager.scanning {
                WelcomeView()
            } else {
                VStack(spacing: 0) {

                    // Search bar
                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.secondary)
                            .font(.system(size: 13))
                        TextField("Search checks, CIS IDs, status…", text: $searchText)
                            .textFieldStyle(.plain)
                            .font(.system(size: 13))
                        if !searchText.isEmpty {
                            Button { searchText = "" } label: {
                                Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                            }.buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
                    .background(Color.primary.opacity(0.04))

                    Divider()

                    // Filter + Sort toolbar
                    FilterSortBar(
                        statusFilter: $statusFilter,
                        severityFilter: $severityFilter,
                        sortOrder: $sortOrder,
                        severities: severities,
                        failedCount: failedCount,
                        passedCount: passedCount,
                        warnedCount: warnedCount,
                        advisoryCount: advisoryCount
                    )

                    Divider()

                    // Severity distribution bar (shown when there are failures)
                    let failedInBase = base.filter { $0.checkstatus == "Red" }
                    if !failedInBase.isEmpty {
                        SeverityDistributionBar(results: base)
                        Divider()
                    }

                    // Live scan progress (shown while scanning; list still visible below)
                    if scanManager.scanning {
                        ScanProgressBanner(
                            progress: scanManager.progress,
                            completed: scanManager.scanResults.count
                        )
                        Divider()
                    }

                    // Stats + export row
                    if !scanManager.scanResults.isEmpty {
                        HStack(spacing: 8) {
                            Text(hasFilters
                                 ? "Showing \(results.count) of \(base.count) checks"
                                 : "\(base.count) check\(base.count == 1 ? "" : "s")")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .padding(.leading, 12)
                            Spacer()
                            if !scanManager.scanning {
                                if fixableCount > 0 {
                                    Button {
                                        showFixSheet = true
                                    } label: {
                                        Label("Fix \(fixableCount) Issue\(fixableCount == 1 ? "" : "s")",
                                              systemImage: "bolt.fill")
                                            .font(.system(size: 11, weight: .semibold))
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                                    .tint(.red)
                                    .sheet(isPresented: $showFixSheet) {
                                        FixAllSheet(scanManager: scanManager)
                                    }
                                }
                                ExportButtons(scanResults: scanManager.scanResults)
                            }
                        }
                        .padding(.vertical, 5)
                        .background(Color.primary.opacity(0.02))
                        Divider()
                    }

                    // Results list or empty-filter state
                    if results.isEmpty && !scanManager.scanning {
                        EmptyFilterView(hasFilters: hasFilters) {
                            statusFilter = .all
                            severityFilter = "Any"
                            searchText = ""
                        }
                    } else {
                        List(selection: Binding(
                            get: { selectedVulnerability?.id },
                            set: { id in
                                selectedVulnerability = scanManager.scanResults.first { $0.id == id }
                            }
                        )) {
                            ForEach(grouped, id: \.section) { group in
                                Section {
                                    ForEach(group.items, id: \.id) { v in
                                        VulnerabilityRow(vulnerability: v)
                                            .tag(v.id)
                                    }
                                } header: {
                                    SectionHeader(title: group.section, items: group.items)
                                }
                            }
                        }
                        .listStyle(.inset)
                        .animation(.default, value: scanManager.scanResults.count)
                    }
                }
            }
        }
        .navigationTitle(selectedCategory ?? "All Checks")
        .onChange(of: selectedCategory) { _ in
            statusFilter = .all
            severityFilter = "Any"
        }
    }
}

// MARK: - Filter + Sort Bar

struct FilterSortBar: View {
    @Binding var statusFilter: StatusFilter
    @Binding var severityFilter: String
    @Binding var sortOrder: ResultSortOrder
    let severities: [String]
    let failedCount: Int
    let passedCount: Int
    let warnedCount: Int
    let advisoryCount: Int

    var body: some View {
        HStack(spacing: 4) {
            FilterPill(filter: .all,      isSelected: statusFilter == .all,      count: nil)           { statusFilter = .all }
            FilterPill(filter: .failed,   isSelected: statusFilter == .failed,   count: failedCount)   { statusFilter = .failed }
            FilterPill(filter: .passed,   isSelected: statusFilter == .passed,   count: passedCount)   { statusFilter = .passed }
            FilterPill(filter: .warned,   isSelected: statusFilter == .warned,   count: warnedCount)   { statusFilter = .warned }
            FilterPill(filter: .advisory, isSelected: statusFilter == .advisory, count: advisoryCount) { statusFilter = .advisory }

            Spacer(minLength: 4)

            Menu {
                ForEach(severities, id: \.self) { sev in
                    Button(sev) { severityFilter = sev }
                }
            } label: {
                HStack(spacing: 3) {
                    Image(systemName: "slider.horizontal.3")
                    Text(severityFilter == "Any" ? "Severity" : severityFilter)
                }
                .font(.system(size: 11))
                .foregroundColor(severityFilter == "Any" ? .secondary : .accentColor)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()

            Color.secondary.opacity(0.25)
                .frame(width: 1, height: 14)

            Menu {
                ForEach(ResultSortOrder.allCases, id: \.rawValue) { order in
                    Button {
                        sortOrder = order
                    } label: {
                        if sortOrder == order {
                            Label(order.rawValue, systemImage: "checkmark")
                        } else {
                            Text(order.rawValue)
                        }
                    }
                }
            } label: {
                HStack(spacing: 3) {
                    Image(systemName: "arrow.up.arrow.down")
                    Text(sortOrder.rawValue)
                }
                .font(.system(size: 11))
                .foregroundColor(.secondary)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }
}

struct FilterPill: View {
    let filter: StatusFilter
    let isSelected: Bool
    let count: Int?
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 3) {
                Image(systemName: filter.icon)
                    .font(.system(size: 10))
                if filter == .all {
                    Text("All")
                        .font(.system(size: 11, weight: .medium))
                } else if let c = count {
                    Text("\(c)")
                        .font(.system(size: 11, weight: .semibold))
                }
            }
            .foregroundColor(isSelected
                ? (filter == .all ? .primary : filter.color)
                : .secondary)
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isSelected
                          ? (filter == .all
                             ? Color.primary.opacity(0.10)
                             : filter.color.opacity(0.13))
                          : (isHovered ? Color.primary.opacity(0.05) : Color.clear))
            )
        }
        .buttonStyle(.plain)
        .onHover { h in withAnimation(.easeInOut(duration: 0.1)) { isHovered = h } }
    }
}

// MARK: - Scan Progress Banner

struct ScanProgressBanner: View {
    let progress: Double
    let completed: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Label("Scanning in progress…", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.accentColor)
                Spacer()
                Text("\(completed) completed · \(Int(progress * 100))%")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .monospacedDigit()
            }
            ProgressView(value: progress)
                .progressViewStyle(.linear)
                .tint(.accentColor)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.accentColor.opacity(0.05))
    }
}

// MARK: - Export Buttons

struct ExportButtons: View {
    let scanResults: [Vulnerability]

    var body: some View {
        HStack(spacing: 4) {
            Button(action: exportHTML) {
                Label("HTML", systemImage: "doc.richtext")
                    .font(.system(size: 11))
            }
            .buttonStyle(.bordered)
            .controlSize(.mini)

            Button(action: exportJSON) {
                Label("JSON", systemImage: "curlybraces")
                    .font(.system(size: 11))
            }
            .buttonStyle(.bordered)
            .controlSize(.mini)
        }
        .padding(.trailing, 8)
    }

    private func exportHTML() {
        let html = HTMLReportGenerator(scanResults: scanResults).generateHTMLReport()
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "MergenReport.html"
        panel.allowedContentTypes = [.html]
        if panel.runModal() == .OK, let url = panel.url {
            try? html.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func exportJSON() {
        let data = JSONReportGenerator(scanResults: scanResults).generateJSONReport()
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "MergenReport.json"
        panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url)
        }
    }
}

// MARK: - Empty Filter State

struct EmptyFilterView: View {
    let hasFilters: Bool
    let clearFilters: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: hasFilters ? "line.3.horizontal.decrease.circle" : "checkmark.seal.fill")
                .font(.system(size: 40))
                .foregroundColor(.secondary.opacity(0.4))
            VStack(spacing: 6) {
                Text(hasFilters ? "No results" : "No checks yet")
                    .font(.headline)
                    .foregroundColor(.secondary)
                Text(hasFilters
                     ? "No checks match your current filters."
                     : "Run a scan to see results.")
                    .font(.caption)
                    .foregroundColor(.secondary.opacity(0.7))
                    .multilineTextAlignment(.center)
            }
            if hasFilters {
                Button("Clear Filters") { clearFilters() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Section Header

struct SectionHeader: View {
    let title: String
    let items: [Vulnerability]

    private var failCount: Int { items.filter { $0.checkstatus == "Red" }.count }
    private var warnCount: Int { items.filter { $0.checkstatus == "Yellow" }.count }
    private var passCount: Int { items.filter { $0.checkstatus == "Green" }.count }

    var body: some View {
        HStack(spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .textCase(nil)
            Spacer()
            HStack(spacing: 4) {
                if failCount > 0 { StatusBadge(count: failCount, color: .red) }
                if warnCount > 0 { StatusBadge(count: warnCount, color: .orange) }
                if passCount > 0 { StatusBadge(count: passCount, color: .green) }
            }
        }
    }
}

struct StatusBadge: View {
    let count: Int
    let color: Color

    var body: some View {
        Text("\(count)")
            .font(.system(size: 10, weight: .semibold, design: .rounded))
            .foregroundColor(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(color.opacity(0.12))
            .cornerRadius(5)
    }
}

// MARK: - Vulnerability Row

struct VulnerabilityRow: View {
    let vulnerability: Vulnerability

    private var statusColor: Color {
        switch vulnerability.checkstatus {
        case "Green":  return .green
        case "Red":    return .red
        case "Yellow": return .orange
        case "Blue":   return .blue
        default:       return .gray
        }
    }

    private var statusIcon: String {
        switch vulnerability.checkstatus {
        case "Green":  return "checkmark.circle.fill"
        case "Red":    return "xmark.circle.fill"
        case "Yellow": return "exclamationmark.triangle.fill"
        case "Blue":   return "info.circle.fill"
        default:       return "questionmark.circle"
        }
    }

    private var severityColor: Color {
        switch vulnerability.severity.lowercased() {
        case "critical": return .red
        case "high":     return .orange
        case "medium":   return Color(red: 0.8, green: 0.65, blue: 0)
        case "low":      return .blue
        default:         return .gray
        }
    }

    private var accentColor: Color {
        switch vulnerability.checkstatus {
        case "Red":    return statusColor.opacity(0.65)
        case "Yellow": return statusColor.opacity(0.55)
        default:       return .clear
        }
    }

    var body: some View {
        HStack(spacing: 0) {

            // Left accent bar (coloured for Red/Yellow, invisible for others)
            RoundedRectangle(cornerRadius: 2)
                .fill(accentColor)
                .frame(width: 3)
                .padding(.vertical, 5)

            HStack(spacing: 10) {
                Image(systemName: statusIcon)
                    .foregroundColor(statusColor)
                    .font(.system(size: 15))
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        if !vulnerability.cisID.isEmpty {
                            Text(vulnerability.cisID)
                                .font(.system(size: 10, weight: .medium, design: .monospaced))
                                .foregroundColor(.secondary)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 2)
                                .background(Color.primary.opacity(0.06))
                                .cornerRadius(4)
                        }
                        Text(vulnerability.name)
                            .font(.system(size: 13, weight: .medium))
                            .lineLimit(1)
                    }
                    if let status = vulnerability.status, !status.isEmpty {
                        Text(status)
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer()

                // Only show severity chip for High/Critical to reduce noise
                if vulnerability.severity.lowercased() == "high" || vulnerability.severity.lowercased() == "critical" {
                    Text(vulnerability.severity)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(severityColor)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(severityColor.opacity(0.10))
                        .cornerRadius(5)
                }
            }
            .padding(.leading, 8)
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Severity Distribution Bar

struct SeverityDistributionBar: View {
    let results: [Vulnerability]

    private var failed:   [Vulnerability] { results.filter { $0.checkstatus == "Red" } }
    private var critical: Int { failed.filter { $0.severity.lowercased() == "critical" }.count }
    private var high:     Int { failed.filter { $0.severity.lowercased() == "high"     }.count }
    private var medium:   Int { failed.filter { $0.severity.lowercased() == "medium"   }.count }
    private var low:      Int { failed.filter { $0.severity.lowercased() == "low"      }.count }
    private var total:    Int { failed.count }

    var body: some View {
        Group {
            if total > 0 {
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text("Risk Profile")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("\(total) failed")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }

                    // Stacked bar
                    GeometryReader { geo in
                        let tw = geo.size.width
                        let tc = CGFloat(total)
                        ZStack(alignment: .leading) {
                            // Background track
                            RoundedRectangle(cornerRadius: 3)
                                .fill(Color.primary.opacity(0.06))
                            // Segments
                            HStack(spacing: 0) {
                                if critical > 0 {
                                    Color.red
                                        .frame(width: tw * CGFloat(critical) / tc)
                                }
                                if high > 0 {
                                    Color.orange
                                        .frame(width: tw * CGFloat(high) / tc)
                                }
                                if medium > 0 {
                                    Color(red: 0.85, green: 0.70, blue: 0)
                                        .frame(width: tw * CGFloat(medium) / tc)
                                }
                                if low > 0 {
                                    Color.blue // fills remainder
                                }
                            }
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    .frame(height: 6)

                    // Legend
                    HStack(spacing: 10) {
                        if critical > 0 { SevLegendDot(label: "\(critical) Critical", color: .red) }
                        if high     > 0 { SevLegendDot(label: "\(high) High",         color: .orange) }
                        if medium   > 0 { SevLegendDot(label: "\(medium) Med",        color: Color(red: 0.85, green: 0.70, blue: 0)) }
                        if low      > 0 { SevLegendDot(label: "\(low) Low",           color: .blue) }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Color.primary.opacity(0.02))
            }
        }
    }
}

private struct SevLegendDot: View {
    let label: String
    let color: Color
    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Welcome View

struct WelcomeView: View {
    @State private var isRotating = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            VStack(spacing: 12) {
                // Shield with animated radar rings
                ZStack {
                    // Outer slow ring (counter-clockwise)
                    Circle()
                        .strokeBorder(
                            style: StrokeStyle(lineWidth: 1, dash: [3, 9])
                        )
                        .foregroundColor(.accentColor.opacity(0.13))
                        .frame(width: 118, height: 118)
                        .rotationEffect(.degrees(isRotating ? -360 : 0))
                        .animation(
                            .linear(duration: 16).repeatForever(autoreverses: false),
                            value: isRotating
                        )

                    // Inner faster ring (clockwise)
                    Circle()
                        .strokeBorder(
                            style: StrokeStyle(lineWidth: 1.5, dash: [6, 5])
                        )
                        .foregroundColor(.accentColor.opacity(0.28))
                        .frame(width: 88, height: 88)
                        .rotationEffect(.degrees(isRotating ? 360 : 0))
                        .animation(
                            .linear(duration: 9).repeatForever(autoreverses: false),
                            value: isRotating
                        )

                    Image(systemName: "shield.lefthalf.filled.slash")
                        .font(.system(size: 52))
                        .foregroundStyle(
                            LinearGradient(
                                colors: [.accentColor, .accentColor.opacity(0.55)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                }
                .frame(width: 120, height: 120)
                .onAppear { isRotating = true }

                VStack(spacing: 6) {
                    Text("macOS Security Audit")
                        .font(.system(size: 22, weight: .bold, design: .rounded))
                    Text("CIS Apple macOS 26 Tahoe Benchmark v1.0.0")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                FeatureRow(icon: "lock.shield.fill",      color: .blue,   title: "90+ Automated Checks",      desc: "All CIS Tahoe benchmark sections")
                FeatureRow(icon: "cpu.fill",              color: .purple, title: "Apple Intelligence Checks",  desc: "New 2.5.x AI privacy checks for Tahoe")
                FeatureRow(icon: "line.3.horizontal.decrease.circle.fill", color: .orange, title: "Filter, Sort & Search", desc: "Quickly find failures, warnings, or specific checks")
                FeatureRow(icon: "square.and.arrow.up",   color: .green,  title: "Export Reports",             desc: "HTML and JSON formats")
            }
            .padding(16)
            .background(Color.primary.opacity(0.04))
            .cornerRadius(12)

            Text("Choose a category in the sidebar, then press Start Scan")
                .font(.caption)
                .foregroundColor(.secondary)

            Spacer()
        }
        .padding(36)
        .frame(maxWidth: 460)
    }
}

struct FeatureRow: View {
    let icon: String
    let color: Color
    let title: String
    let desc: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundColor(color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(desc).font(.caption).foregroundColor(.secondary)
            }
        }
    }
}
