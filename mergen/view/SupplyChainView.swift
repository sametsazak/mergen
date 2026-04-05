//
//  SupplyChainView.swift
//  mergen
//
//  Supply Chain Threat Surface — dedicated scan view.
//  Two-pane layout: findings list (left) + detail panel (right).
//

import SwiftUI
import AppKit

// MARK: - Root View

struct SupplyChainView: View {
    @ObservedObject var scanner: SupplyChainScanner

    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    var body: some View {
        VStack(spacing: 0) {
            SupplyChainTopBar(scanner: scanner)
            Divider()

            if !scanner.hasResults && !scanner.isScanning {
                SupplyChainIdleView(scanner: scanner)
            } else {
                SupplyChainResultsView(scanner: scanner)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Top Bar

struct SupplyChainTopBar: View {
    @ObservedObject var scanner: SupplyChainScanner
    @State private var showFixAll = false

    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    private var criticalCount: Int { scanner.findings.filter { $0.severity == .critical }.count }
    private var highCount:     Int { scanner.findings.filter { $0.severity == .high     }.count }
    private var mediumCount:   Int { scanner.findings.filter { $0.severity == .medium   }.count }
    private var totalCount:    Int { scanner.findings.count }

    var body: some View {
        HStack(spacing: 0) {
            // Branding
            HStack(spacing: 7) {
                Image(systemName: "checkerboard.shield")
                    .font(.system(size: 14))
                    .foregroundStyle(LinearGradient(
                        colors: [Color(red: 0.65, green: 0.52, blue: 1.00), accent],
                        startPoint: .top, endPoint: .bottom
                    ))
                VStack(alignment: .leading, spacing: 0) {
                    Text("Supply Chain")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                    Text("Threat Surface")
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(.secondary)
                        .tracking(0.3)
                }
            }
            .padding(.horizontal, 16)

            vDivider()

            // Stats (only after scan)
            if scanner.hasResults {
                HStack(spacing: 16) {
                    statChip(totalCount,    "Total",    .secondary)
                    statChip(criticalCount, "Critical", Color(red: 0.90, green: 0.15, blue: 0.15))
                    statChip(highCount,     "High",     Color(red: 0.85, green: 0.25, blue: 0.25))
                    statChip(mediumCount,   "Medium",   Color(red: 0.80, green: 0.52, blue: 0.10))
                }
                .padding(.horizontal, 14)

                vDivider()
            }

            // Source pills
            HStack(spacing: 6) {
                SourcePill(label: "OSV",
                           state: scanner.sourceStatus.osvReachable.map { $0 ? .ok : .fail } ?? .unknown)
                SourcePill(label: "npm",
                           state: scanner.sourceStatus.npmInstalled  ? .ok : .missing)
                SourcePill(label: "pip3",
                           state: scanner.sourceStatus.pipInstalled  ? .ok : .missing)
                SourcePill(label: "brew",
                           state: scanner.sourceStatus.brewInstalled ? .ok : .missing)
            }
            .padding(.horizontal, 14)

            Spacer()

            // Progress
            if scanner.isScanning {
                HStack(spacing: 7) {
                    ProgressView()
                        .scaleEffect(0.6)
                        .frame(width: 14, height: 14)
                    Text("Scanning… \(Int(scanner.progress * 100))%")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }
                .padding(.horizontal, 14)
            }

            // Fix All + Scan / Rescan buttons
            if !scanner.isScanning {
                HStack(spacing: 8) {
                    let fixableCount = scanner.findings.filter { $0.isFixable }.count
                    if scanner.hasResults && fixableCount > 0 {
                        Button {
                            showFixAll = true
                        } label: {
                            Label("Fix All (\(fixableCount))", systemImage: "bolt.fill")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        .tint(Color(red: 0.20, green: 0.60, blue: 0.30))
                    }

                    Button(action: scanner.startScan) {
                        Label(scanner.hasResults ? "Rescan" : "Scan Now",
                              systemImage: scanner.hasResults ? "arrow.clockwise" : "magnifyingglass.circle.fill")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .tint(accent)
                }
                .padding(.trailing, 14)
            }
        }
        .frame(height: 52)
        .background(Color(NSColor.windowBackgroundColor))
        .sheet(isPresented: $showFixAll) {
            SCFixAllSheet(scanner: scanner)
        }
    }

    @ViewBuilder
    private func vDivider() -> some View {
        Rectangle().fill(Color.primary.opacity(0.08)).frame(width: 1, height: 24)
    }

    @ViewBuilder
    private func statChip(_ count: Int, _ label: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Text("\(count)")
                .font(.system(size: 14, weight: .bold, design: .rounded))
                .foregroundColor(color)
                .monospacedDigit()
            Text(label)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Source Pill

enum SourcePillState { case ok, fail, missing, unknown }

struct SourcePill: View {
    let label: String
    let state: SourcePillState

    private var dot: Color {
        switch state {
        case .ok:      return Color(red: 0.07, green: 0.66, blue: 0.47)
        case .fail:    return Color(red: 0.85, green: 0.25, blue: 0.25)
        case .missing: return Color.secondary.opacity(0.6)
        case .unknown: return Color.secondary.opacity(0.4)
        }
    }
    private var textColor: Color {
        state == .missing ? .secondary : .primary
    }
    private var tooltip: String {
        switch state {
        case .ok:      return "\(label) is available"
        case .fail:    return "\(label) is unreachable"
        case .missing: return "\(label) is not installed"
        case .unknown: return "\(label) — not yet checked"
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(dot).frame(width: 5, height: 5)
            Text(label)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(textColor)
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            RoundedRectangle(cornerRadius: 5)
                .fill(Color.primary.opacity(0.05))
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.primary.opacity(0.08), lineWidth: 1))
        )
        .help(tooltip)
    }
}

// MARK: - Idle / Pre-scan View

struct SupplyChainIdleView: View {
    @ObservedObject var scanner: SupplyChainScanner
    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    var body: some View {
        VStack(spacing: 28) {
            Spacer()

            Image(systemName: "checkerboard.shield")
                .font(.system(size: 56))
                .foregroundStyle(LinearGradient(
                    colors: [Color(red: 0.65, green: 0.52, blue: 1.00), accent],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                ))
                .shadow(color: accent.opacity(0.3), radius: 16)

            VStack(spacing: 6) {
                Text("Supply Chain Threat Surface")
                    .font(.system(size: 22, weight: .bold, design: .rounded))
                Text("Scans for malicious packages, persistence mechanisms,\nunvetted Homebrew taps, and risky LLM model files.")
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                SCFeatureCard(icon: "bolt.trianglebadge.exclamationmark.fill",
                              color: Color(red: 0.85, green: 0.25, blue: 0.25),
                              title: "Launch Agents & Cron",
                              subtitle: "Persistence mechanisms & cron jobs")
                SCFeatureCard(icon: "shippingbox.fill",
                              color: Color(red: 0.80, green: 0.52, blue: 0.10),
                              title: "npm Packages",
                              subtitle: "Postinstall scripts + CVE database")
                SCFeatureCard(icon: "chevron.left.forwardslash.chevron.right",
                              color: Color(red: 0.20, green: 0.52, blue: 0.85),
                              title: "Python Packages",
                              subtitle: "pip3 list scanned via OSV")
                SCFeatureCard(icon: "cup.and.saucer.fill",
                              color: Color(red: 0.85, green: 0.45, blue: 0.15),
                              title: "Homebrew Taps",
                              subtitle: "Flags unofficial unvetted taps")
                SCFeatureCard(icon: "cpu",
                              color: Color(red: 0.55, green: 0.25, blue: 0.85),
                              title: "LLM Model Files",
                              subtitle: "Pickle files & models outside known dirs")
                SCFeatureCard(icon: "globe",
                              color: Color(red: 0.07, green: 0.66, blue: 0.47),
                              title: "OSV CVE Database",
                              subtitle: "Google's open vulnerability database")
            }
            .frame(maxWidth: 560)

            Button(action: scanner.startScan) {
                Label("Start Threat Scan", systemImage: "magnifyingglass.circle.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .tint(accent)

            Spacer()
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct SCFeatureCard: View {
    let icon: String
    let color: Color
    let title: String
    let subtitle: String
    @State private var hovered = false

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(color.opacity(0.12))
                    .frame(width: 34, height: 34)
                Image(systemName: icon)
                    .font(.system(size: 15))
                    .foregroundColor(color)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 12, weight: .semibold)).foregroundColor(.primary)
                Text(subtitle).font(.system(size: 10)).foregroundColor(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(NSColor.windowBackgroundColor))
                .shadow(color: .black.opacity(hovered ? 0.10 : 0.05), radius: hovered ? 8 : 4, y: 2)
        )
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(NSColor.separatorColor).opacity(0.6), lineWidth: 1))
        .scaleEffect(hovered ? 1.01 : 1.0)
        .animation(.easeInOut(duration: 0.15), value: hovered)
        .onHover { h in hovered = h }
    }
}

// MARK: - Results View (two-pane)

struct SupplyChainResultsView: View {
    @ObservedObject var scanner: SupplyChainScanner
    @State private var selectedFinding: ThreatFinding? = nil

    var body: some View {
        HStack(spacing: 0) {

            // ── Left pane: findings list ─────────────────────────────────
            VStack(spacing: 0) {
                if scanner.isScanning {
                    SCProgressBanner(progress: scanner.progress, findings: scanner.findings.count)
                        .padding(.horizontal, 10)
                        .padding(.top, 10)
                        .padding(.bottom, 4)
                }
                ScrollView {
                    VStack(spacing: 10) {
                        ForEach(ThreatCategory.allCases, id: \.self) { cat in
                            let catFindings = scanner.findings.filter { $0.category == cat }
                            CategorySection(
                                category: cat,
                                findings: catFindings,
                                isScanning: scanner.isScanning,
                                selectedFinding: $selectedFinding
                            )
                            .padding(.horizontal, 10)
                        }
                        Spacer(minLength: 16)
                    }
                    .padding(.vertical, 10)
                }
            }
            .frame(width: 370)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.5))

            Divider()

            // ── Right pane: detail ───────────────────────────────────────
            ThreatFindingDetailPanel(finding: selectedFinding, scanner: scanner)
        }
    }
}

// MARK: - Progress Banner

struct SCProgressBanner: View {
    let progress: Double
    let findings: Int

    var body: some View {
        HStack(spacing: 12) {
            ProgressView(value: progress)
                .progressViewStyle(.linear)
                .tint(Color(red: 0.42, green: 0.26, blue: 0.88))
                .frame(maxWidth: .infinity)
            Text("\(findings) finding\(findings == 1 ? "" : "s") so far")
                .font(.system(size: 11))
                .foregroundColor(.secondary)
                .monospacedDigit()
                .fixedSize()
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.primary.opacity(0.04))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.07), lineWidth: 1))
        )
    }
}

// MARK: - Category Section

struct CategorySection: View {
    let category  : ThreatCategory
    let findings  : [ThreatFinding]
    let isScanning: Bool
    @Binding var selectedFinding: ThreatFinding?

    @State private var expanded = true

    private var sorted: [ThreatFinding] {
        findings.sorted { $0.severity < $1.severity }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Section header
            Button(action: { withAnimation(.easeInOut(duration: 0.2)) { expanded.toggle() } }) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 7)
                            .fill(category.color.opacity(0.12))
                            .frame(width: 28, height: 28)
                        Image(systemName: category.icon)
                            .font(.system(size: 12))
                            .foregroundColor(category.color)
                    }

                    Text(category.rawValue)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(.primary)

                    if !findings.isEmpty {
                        Text("\(findings.count)")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(category.color)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(category.color.opacity(0.12)))
                    }

                    Spacer()

                    if isScanning && findings.isEmpty {
                        ProgressView().scaleEffect(0.5).frame(width: 12, height: 12)
                    } else if findings.isEmpty {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 0.07, green: 0.66, blue: 0.47))
                            Text("All clear")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                    }

                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
            .buttonStyle(.plain)

            // Findings
            if expanded && !sorted.isEmpty {
                Divider().padding(.horizontal, 14)

                ForEach(Array(sorted.enumerated()), id: \.element.id) { index, finding in
                    FindingRow(finding: finding, selectedFinding: $selectedFinding)
                    if index < sorted.count - 1 {
                        Divider().padding(.leading, 14)
                    }
                }
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(NSColor.windowBackgroundColor))
                .shadow(color: .black.opacity(0.06), radius: 6, y: 2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(findings.isEmpty ? Color(NSColor.separatorColor).opacity(0.5)
                        : category.color.opacity(0.25), lineWidth: 1)
        )
    }
}

// MARK: - Finding Row (selectable, compact)

struct FindingRow: View {
    let finding: ThreatFinding
    @Binding var selectedFinding: ThreatFinding?

    private var isSelected: Bool { selectedFinding?.id == finding.id }
    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    var body: some View {
        Button(action: { selectedFinding = finding }) {
            HStack(alignment: .center, spacing: 10) {
                // Severity dot
                Circle()
                    .fill(finding.severity.color)
                    .frame(width: 7, height: 7)
                    .padding(.leading, 4)

                // Title + location
                VStack(alignment: .leading, spacing: 2) {
                    Text(finding.title)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                    if let loc = finding.location, !loc.isEmpty {
                        Text(loc)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary.opacity(0.8))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                // Source badge + fixable indicator
                VStack(alignment: .trailing, spacing: 3) {
                    SourceBadge(source: finding.source)
                    if finding.isFixable {
                        Image(systemName: "bolt.fill")
                            .font(.system(size: 8))
                            .foregroundColor(accent.opacity(0.7))
                    }
                }

                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundColor(.secondary.opacity(0.4))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(
                isSelected
                    ? accent.opacity(0.10)
                    : Color.clear
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Source Badge

struct SourceBadge: View {
    let source: FindingSource

    private var color: Color {
        switch source {
        case .localAnalysis: return Color(red: 0.42, green: 0.26, blue: 0.88)
        case .osv:           return Color(red: 0.07, green: 0.66, blue: 0.47)
        case .pipAudit:      return Color(red: 0.20, green: 0.52, blue: 0.85)
        }
    }

    var body: some View {
        Text(source.rawValue)
            .font(.system(size: 9, weight: .semibold))
            .foregroundColor(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 4)
                    .fill(color.opacity(0.10))
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(color.opacity(0.25), lineWidth: 0.5))
            )
    }
}

// MARK: - Detail Panel

struct ThreatFindingDetailPanel: View {
    let finding: ThreatFinding?
    @ObservedObject var scanner: SupplyChainScanner

    var body: some View {
        Group {
            if let f = finding {
                ThreatFindingDetailView(finding: f, scanner: scanner)
            } else {
                SCEmptyDetailView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Empty Detail State

struct SCEmptyDetailView: View {
    var body: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(Color.secondary.opacity(0.07))
                    .frame(width: 80, height: 80)
                Image(systemName: "checkerboard.shield")
                    .font(.system(size: 34))
                    .foregroundColor(.secondary.opacity(0.30))
            }
            VStack(spacing: 5) {
                Text("Select a finding")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(.secondary)
                Text("Click any row to see details,\nremediation steps, and fix options.")
                    .font(.caption)
                    .foregroundColor(.secondary.opacity(0.65))
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Threat Finding Detail View

struct ThreatFindingDetailView: View {
    let finding: ThreatFinding
    @ObservedObject var scanner: SupplyChainScanner
    @State private var remediationCopied = false

    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    private var hasShellCommands: Bool {
        let cmds = ["pip3 ", "npm ", "brew ", "launchctl ", "rm ", "/bin/", "/usr/"]
        return cmds.contains { finding.remediation.contains($0) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {

                // ── Header ────────────────────────────────────────────────
                VStack(alignment: .leading, spacing: 12) {

                    HStack(alignment: .top, spacing: 12) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10)
                                .fill(finding.category.color.opacity(0.12))
                                .frame(width: 38, height: 38)
                            Image(systemName: finding.category.icon)
                                .font(.system(size: 17))
                                .foregroundColor(finding.category.color)
                        }

                        VStack(alignment: .leading, spacing: 7) {
                            Text(finding.title)
                                .font(.system(size: 15, weight: .semibold))
                                .fixedSize(horizontal: false, vertical: true)

                            HStack(spacing: 6) {
                                BadgeView(text: finding.severity.rawValue, color: finding.severity.color)
                                BadgeView(text: finding.category.rawValue, color: finding.category.color)
                                SourceBadge(source: finding.source)
                            }
                        }
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)

                Divider()

                // ── Sections ──────────────────────────────────────────────
                VStack(alignment: .leading, spacing: 22) {

                    // Description — always shown
                    DetailSection(title: "Description", icon: "doc.text") {
                        detailText(finding.detail)
                    }

                    // Remediation
                    DetailSection(title: "Remediation", icon: "wrench.and.screwdriver") {
                        VStack(alignment: .leading, spacing: 10) {
                            if hasShellCommands {
                                Text(finding.remediation)
                                    .font(.system(size: 12, design: .monospaced))
                                    .fixedSize(horizontal: false, vertical: true)
                                    .padding(10)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color.primary.opacity(0.05))
                                    .cornerRadius(7)
                            } else {
                                Text(finding.remediation)
                                    .font(.system(size: 13))
                                    .fixedSize(horizontal: false, vertical: true)
                            }

                            HStack(spacing: 8) {
                                Button(action: copyRemediation) {
                                    Label(remediationCopied ? "Copied!" : "Copy",
                                          systemImage: remediationCopied ? "checkmark" : "doc.on.doc")
                                        .font(.system(size: 12))
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .tint(remediationCopied ? .green : .accentColor)

                                if finding.isFixable {
                                    SCAutoFixButton(finding: finding, scanner: scanner)
                                }
                            }
                        }
                    }

                    // CVE References + metadata row
                    if !finding.cveIDs.isEmpty || finding.publishedDate != nil || finding.fixedVersion != nil {
                        DetailSection(title: "Vulnerability Info", icon: "tag.fill") {
                            VStack(alignment: .leading, spacing: 10) {
                                // CVE ID pills
                                if !finding.cveIDs.isEmpty {
                                    ScrollView(.horizontal, showsIndicators: false) {
                                        HStack(spacing: 6) {
                                            ForEach(finding.cveIDs, id: \.self) { cve in
                                                Text(cve)
                                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                                    .foregroundColor(accent)
                                                    .padding(.horizontal, 8)
                                                    .padding(.vertical, 4)
                                                    .background(
                                                        RoundedRectangle(cornerRadius: 5)
                                                            .fill(accent.opacity(0.10))
                                                    )
                                            }
                                        }
                                    }
                                }
                                // Published date + Fixed version
                                HStack(spacing: 16) {
                                    if let date = finding.publishedDate {
                                        HStack(spacing: 4) {
                                            Image(systemName: "calendar")
                                                .font(.system(size: 11))
                                                .foregroundColor(.secondary)
                                            Text("Published \(date)")
                                                .font(.system(size: 11))
                                                .foregroundColor(.secondary)
                                        }
                                    }
                                    if let fixed = finding.fixedVersion {
                                        HStack(spacing: 4) {
                                            Image(systemName: "checkmark.shield.fill")
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 0.07, green: 0.66, blue: 0.47))
                                            Text("Fixed in \(fixed)")
                                                .font(.system(size: 11))
                                                .foregroundColor(Color(red: 0.07, green: 0.66, blue: 0.47))
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Advisory References
                    if !finding.references.isEmpty {
                        DetailSection(title: "References", icon: "link") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(finding.references.prefix(6), id: \.self) { url in
                                    if let link = URL(string: url) {
                                        Link(destination: link) {
                                            HStack(spacing: 6) {
                                                Image(systemName: "arrow.up.right.square")
                                                    .font(.system(size: 10))
                                                    .foregroundColor(accent)
                                                Text(url)
                                                    .font(.system(size: 11))
                                                    .foregroundColor(accent)
                                                    .lineLimit(1)
                                                    .truncationMode(.middle)
                                                    .frame(maxWidth: .infinity, alignment: .leading)
                                            }
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                                if finding.references.count > 6 {
                                    Text("+ \(finding.references.count - 6) more")
                                        .font(.system(size: 10))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }

                    // Location
                    if let loc = finding.location, !loc.isEmpty {
                        DetailSection(title: "Location", icon: "mappin.circle") {
                            Text(loc)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .padding(20)
            }
        }
    }

    /// Renders OSV markdown details (### headings, **bold**, `code`, plain URLs).
    /// Falls back to a plain Text if AttributedString parsing fails.
    @ViewBuilder
    private func detailText(_ text: String) -> some View {
        if let attr = try? AttributedString(markdown: text,
                                            options: .init(interpretedSyntax: .full)) {
            Text(attr)
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Text(text)
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func copyRemediation() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(finding.remediation, forType: .string)
        remediationCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { remediationCopied = false }
    }
}

// MARK: - Supply Chain Auto-Fix Button

struct SCAutoFixButton: View {
    let finding : ThreatFinding
    @ObservedObject var scanner: SupplyChainScanner

    private var isFixing   : Bool  { scanner.fixingIDs.contains(finding.id) }
    private var result     : Bool? { scanner.fixResults[finding.id] }
    private var isCancelled: Bool  { scanner.fixCancelled.contains(finding.id) }
    private var isFixed    : Bool  { result == true }

    var body: some View {
        Group {
            if isFixing {
                HStack(spacing: 5) {
                    ProgressView().scaleEffect(0.7)
                    Text("Fixing…").font(.system(size: 12))
                }
                .foregroundColor(.secondary)

            } else if isFixed {
                Label("Fixed!", systemImage: "checkmark.seal.fill")
                    .font(.system(size: 12))
                    .foregroundColor(.green)

            } else if isCancelled {
                Label("Cancelled", systemImage: "xmark.circle")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)

            } else if let r = result, !r {
                Label("Failed — try manually", systemImage: "exclamationmark.triangle")
                    .font(.system(size: 12))
                    .foregroundColor(.red)

            } else {
                Button {
                    scanner.applyFix(for: finding)
                } label: {
                    Label(
                        finding.fixRequiresAdmin ? "Fix (Admin)" : "Fix Automatically",
                        systemImage: "bolt.fill"
                    )
                    .font(.system(size: 12))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.primary)
            }
        }
        .animation(.default, value: isFixing)
        .animation(.default, value: isFixed)
    }
}

// MARK: - Fix All Sheet

struct SCFixAllSheet: View {
    @ObservedObject var scanner: SupplyChainScanner
    @Environment(\.dismiss) private var dismiss

    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    private var fixable: [ThreatFinding] {
        scanner.findings
            .filter { $0.isFixable }
            .sorted { $0.severity < $1.severity }
    }
    private var adminCount:  Int  { fixable.filter {  $0.fixRequiresAdmin }.count }
    private var userCount:   Int  { fixable.filter { !$0.fixRequiresAdmin }.count }
    private var isFixing:    Bool { !scanner.fixingIDs.isEmpty }
    private var doneCount:   Int  { fixable.filter { scanner.fixResults[$0.id] != nil || scanner.fixCancelled.contains($0.id) }.count }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {

            // ── Header ───────────────────────────────────────────────────────
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Fix All Issues")
                        .font(.system(size: 18, weight: .bold))
                    Text("\(fixable.count) finding\(fixable.count == 1 ? "" : "s") can be fixed automatically")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundColor(.secondary.opacity(0.6))
                }
                .buttonStyle(.plain)
            }
            .padding(20)

            Divider()

            // ── Admin notice ─────────────────────────────────────────────────
            if adminCount > 0 {
                let warnColor = Color(red: 0.97, green: 0.63, blue: 0.22)
                HStack(spacing: 0) {
                    Rectangle()
                        .fill(warnColor)
                        .frame(width: 4)
                    HStack(spacing: 12) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 20))
                            .foregroundColor(warnColor)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(adminCount) fix\(adminCount == 1 ? "" : "es") require administrator privileges")
                                .font(.system(size: 13, weight: .semibold))
                            Text("You will be prompted once for your password. All admin fixes run together.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(warnColor.opacity(0.08))
                Divider()
            }

            // ── List ─────────────────────────────────────────────────────────
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(fixable) { finding in
                        SCFixRowItem(finding: finding, scanner: scanner)
                        Divider().padding(.leading, 48)
                    }
                }
            }

            Divider()

            // ── Footer ───────────────────────────────────────────────────────
            HStack(spacing: 10) {
                if isFixing {
                    HStack(spacing: 6) {
                        ProgressView().scaleEffect(0.7)
                        Text("Applying fixes…")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                } else if doneCount > 0 {
                    let successCount = fixable.filter { scanner.fixResults[$0.id] == true }.count
                    Label("\(successCount)/\(doneCount) succeeded", systemImage: "checkmark.circle")
                        .font(.system(size: 11))
                        .foregroundColor(successCount == doneCount ? .green : .secondary)
                }

                Spacer()

                Button("Close") { dismiss() }
                    .buttonStyle(.bordered)

                if !isFixing {
                    Button {
                        scanner.fixAll(fixable)
                    } label: {
                        Label("Apply All Fixes", systemImage: "bolt.fill")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(
                                LinearGradient(
                                    colors: [accent.opacity(0.9), accent],
                                    startPoint: .leading, endPoint: .trailing
                                )
                            )
                            .cornerRadius(9)
                            .shadow(color: accent.opacity(0.30), radius: 5, y: 2)
                    }
                    .buttonStyle(.plain)
                    .disabled(fixable.isEmpty)
                    .opacity(fixable.isEmpty ? 0.5 : 1)
                }
            }
            .padding(16)
        }
        .frame(width: 580, height: 520)
    }
}

// MARK: - Fix All Row

struct SCFixRowItem: View {
    let finding: ThreatFinding
    @ObservedObject var scanner: SupplyChainScanner

    private var isFixing   : Bool  { scanner.fixingIDs.contains(finding.id) }
    private var result     : Bool? { scanner.fixResults[finding.id] }
    private var isCancelled: Bool  { scanner.fixCancelled.contains(finding.id) }

    private var rowIcon: String {
        if isFixing              { return "arrow.triangle.2.circlepath" }
        if let r = result        { return r ? "checkmark.circle.fill" : "xmark.circle.fill" }
        if isCancelled           { return "minus.circle.fill" }
        return "circle"
    }
    private var rowColor: Color {
        if isFixing              { return .secondary }
        if let r = result        { return r ? .green : .red }
        if isCancelled           { return .secondary }
        return finding.severity.color
    }

    var body: some View {
        HStack(spacing: 12) {
            // Status icon
            Image(systemName: rowIcon)
                .foregroundColor(rowColor)
                .font(.system(size: 16))
                .frame(width: 22)

            // Finding info
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(finding.severity.color)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 3).fill(finding.severity.color.opacity(0.12)))

                    Text(finding.category.rawValue)
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(finding.category.color)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 3).fill(finding.category.color.opacity(0.10)))

                    if finding.fixRequiresAdmin {
                        Label("Admin", systemImage: "lock.fill")
                            .font(.system(size: 9, weight: .medium))
                            .foregroundColor(.orange)
                    }
                }
                Text(finding.title)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
                if let cmd = finding.fixCommand {
                    Text(cmd)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Spacer()

            // Per-row status
            Group {
                if isFixing {
                    ProgressView().scaleEffect(0.7).frame(width: 70)
                } else if result == true {
                    Text("Fixed ✓")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.green)
                } else if isCancelled {
                    Text("Cancelled")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                } else if result == false {
                    Label("Failed", systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.red)
                } else {
                    Button("Fix") { scanner.applyFix(for: finding) }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }
            .frame(minWidth: 70, alignment: .trailing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .animation(.default, value: isFixing)
    }
}
