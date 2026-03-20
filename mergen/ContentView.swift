//
//  ContentView.swift
//  mergen
//

import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var scanManager = ScanManager()
    @State private var selectedVulnerability: Vulnerability? = nil
    @State private var searchText = ""
    @State private var showLogViewer = false

    private var isWelcome: Bool {
        scanManager.scanResults.isEmpty && !scanManager.scanning
    }

    var body: some View {
        Group {
            if isWelcome {
                WelcomeView {
                    scanManager.startScan(category: nil)
                }
            } else {
                VStack(spacing: 0) {
                    ResultsTopBar(scanManager: scanManager)

                    Divider()

                    HStack(spacing: 0) {
                        ResultsListView(
                            scanManager: scanManager,
                            selectedCategory: nil,
                            selectedVulnerability: $selectedVulnerability,
                            searchText: $searchText
                        )
                        .frame(minWidth: 300, idealWidth: 380)

                        Divider()

                        DetailPanelView(
                            vulnerability: selectedVulnerability,
                            scanManager: scanManager
                        )
                        .frame(minWidth: 280)
                    }
                }
            }
        }
        .frame(minWidth: 840, minHeight: 520)
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Button { showLogViewer = true } label: {
                    Label("Audit Log", systemImage: "doc.text.magnifyingglass")
                        .font(.system(size: 12))
                }
                .help("View audit log — scan results and fix history")
                .sheet(isPresented: $showLogViewer) {
                    LogViewerSheet()
                }
            }
        }
    }
}

// MARK: - Results Top Bar

struct ResultsTopBar: View {
    @ObservedObject var scanManager: ScanManager
    @State private var showFixSheet = false

    private let accent = Color(red: 0.42, green: 0.26, blue: 0.88)

    private var automated: [Vulnerability] { scanManager.scanResults.filter { !$0.isManual && $0.checkstatus != "Blue" } }
    private var passCount: Int { automated.filter { $0.checkstatus == "Green" }.count }
    private var failCount: Int { scanManager.scanResults.filter { $0.checkstatus == "Red" }.count }
    private var warnCount: Int { scanManager.scanResults.filter { $0.checkstatus == "Yellow" }.count }
    private var score:     Double { automated.isEmpty ? 0 : Double(passCount) / Double(automated.count) }
    private var fixable:   Int { scanManager.scanResults.filter { $0.isAutoFixable }.count }

    private var scoreColor: Color {
        score >= 0.8 ? Color(red: 0.07, green: 0.66, blue: 0.47)
            : score >= 0.5 ? Color(red: 0.80, green: 0.55, blue: 0.10)
            : Color(red: 0.85, green: 0.25, blue: 0.25)
    }
    private var scoreLabel: String {
        score >= 0.8 ? "GOOD" : score >= 0.5 ? "FAIR" : "AT RISK"
    }

    var body: some View {
        HStack(spacing: 0) {

            // ── Branding ───────────────────────────────────────────────────
            HStack(spacing: 7) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(LinearGradient(
                        colors: [Color(red: 0.65, green: 0.52, blue: 1.00), accent],
                        startPoint: .top, endPoint: .bottom
                    ))
                Text("Mergen")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundColor(.primary)
            }
            .padding(.horizontal, 16)

            divider()

            // ── Score ring ─────────────────────────────────────────────────
            HStack(spacing: 8) {
                ZStack {
                    Circle()
                        .stroke(Color.primary.opacity(0.10), lineWidth: 3)
                        .frame(width: 32, height: 32)
                    Circle()
                        .trim(from: 0, to: score)
                        .stroke(scoreColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .frame(width: 32, height: 32)
                        .rotationEffect(.degrees(-90))
                        .animation(.spring(response: 1.1, dampingFraction: 0.82), value: score)
                    Text("\(Int(score * 100))")
                        .font(.system(size: 8, weight: .bold, design: .rounded))
                        .foregroundColor(scoreColor)
                }
                VStack(alignment: .leading, spacing: 0) {
                    Text("\(Int(score * 100))%")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundColor(scoreColor)
                    Text(scoreLabel)
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundColor(.secondary)
                        .tracking(0.6)
                }
            }
            .padding(.horizontal, 14)

            divider()

            // ── Stats ──────────────────────────────────────────────────────
            HStack(spacing: 20) {
                statChip(passCount, "Passed",   Color(red: 0.07, green: 0.66, blue: 0.47))
                statChip(failCount, "Failed",   Color(red: 0.85, green: 0.25, blue: 0.25))
                statChip(warnCount, "Warnings", Color(red: 0.80, green: 0.55, blue: 0.10))
            }
            .padding(.horizontal, 14)

            Spacer()

            // ── Scanning progress ──────────────────────────────────────────
            if scanManager.scanning {
                HStack(spacing: 7) {
                    ProgressView()
                        .scaleEffect(0.6)
                        .frame(width: 14, height: 14)
                    Text("Scanning… \(Int(scanManager.progress * 100))%")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }
                .padding(.horizontal, 14)
            }

            // ── Actions ────────────────────────────────────────────────────
            if !scanManager.scanning {
                HStack(spacing: 6) {
                    if fixable > 0 {
                        Button { showFixSheet = true } label: {
                            Label("Fix \(fixable)", systemImage: "bolt.fill")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        .tint(Color(red: 0.85, green: 0.25, blue: 0.25))
                        .sheet(isPresented: $showFixSheet) {
                            FixAllSheet(scanManager: scanManager)
                        }
                    }

                    Button { scanManager.startScan(category: nil) } label: {
                        Label("Rescan", systemImage: "arrow.clockwise")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Button { scanManager.resetScan() } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .help("Reset")

                    divider()

                    ExportButtons(scanResults: scanManager.scanResults)
                }
                .padding(.horizontal, 12)
            }
        }
        .frame(height: 52)
        .background(Color(NSColor.windowBackgroundColor))
    }

    @ViewBuilder
    private func divider() -> some View {
        Rectangle()
            .fill(Color.primary.opacity(0.08))
            .frame(width: 1, height: 24)
    }

    @ViewBuilder
    private func statChip(_ count: Int, _ label: String, _ color: Color) -> some View {
        HStack(spacing: 5) {
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

// MARK: - Welcome View

struct WelcomeView: View {
    let onScan: () -> Void

    @State private var pulse1     = false
    @State private var pulse2     = false
    @State private var appeared   = false
    @State private var btnHovered = false
    @State private var btnGlow    = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer(minLength: 0)

            // ── Hero ──────────────────────────────────────────────────────
            ZStack {
                // Outer pulse ring
                Circle()
                    .stroke(Color.gray.opacity(pulse2 ? 0 : 0.10), lineWidth: 1)
                    .frame(width: 130, height: 130)
                    .scaleEffect(pulse2 ? 1.45 : 1.0)
                    .animation(.easeOut(duration: 2.8).repeatForever(autoreverses: false), value: pulse2)

                // Inner pulse ring
                Circle()
                    .stroke(Color.gray.opacity(pulse1 ? 0 : 0.16), lineWidth: 1)
                    .frame(width: 105, height: 105)
                    .scaleEffect(pulse1 ? 1.38 : 1.0)
                    .animation(.easeOut(duration: 2.8).repeatForever(autoreverses: false), value: pulse1)

                // Shield icon — white with soft gray shadow
                Image(systemName: "shield.fill")
                    .font(.system(size: 72))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color.white, Color(NSColor.lightGray)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .shadow(color: .black.opacity(0.12), radius: 16, y: 6)
            }
            .frame(width: 210, height: 210)
            .scaleEffect(appeared ? 1.0 : 0.72)
            .opacity(appeared ? 1 : 0)
            .animation(.spring(response: 0.68, dampingFraction: 0.72), value: appeared)
            .onAppear {
                pulse1 = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { pulse2 = true }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { btnGlow = true }
            }

            // ── Title ─────────────────────────────────────────────────────
            VStack(spacing: 6) {
                Text("Welcome to Mergen")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundColor(.primary)
                Text("Start with a thorough security audit of your Mac.")
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .opacity(appeared ? 1 : 0)
            .offset(y: appeared ? 0 : 10)
            .animation(.easeOut(duration: 0.5).delay(0.15), value: appeared)

            // ── Circular scan button ──────────────────────────────────────
            Button(action: onScan) {
                ZStack {
                    Circle()
                        .stroke(Color.primary.opacity(0.10), lineWidth: 1)
                        .frame(width: btnHovered ? 116 : 110, height: btnHovered ? 116 : 110)
                        .animation(.spring(response: 0.3, dampingFraction: 0.65), value: btnHovered)

                    Circle()
                        .fill(
                            LinearGradient(
                                colors: [
                                    Color(NSColor.darkGray),
                                    Color(red: 0.15, green: 0.15, blue: 0.15)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .frame(width: 98, height: 98)
                        // Pulsing glow
                        .shadow(
                            color: .black.opacity(btnGlow ? 0.55 : 0.22),
                            radius: btnGlow ? 28 : 14
                        )
                        .shadow(
                            color: Color.white.opacity(btnGlow ? 0.18 : 0.06),
                            radius: btnGlow ? 22 : 8
                        )
                        .animation(
                            .easeInOut(duration: 2.2).repeatForever(autoreverses: true),
                            value: btnGlow
                        )
                        // Hover pop (separate, non-repeating)
                        .scaleEffect(btnHovered ? 1.05 : 1.0)
                        .animation(.spring(response: 0.3, dampingFraction: 0.65), value: btnHovered)

                    Text("Scan")
                        .font(.system(size: 18, weight: .semibold, design: .rounded))
                        .foregroundColor(.white)
                }
            }
            .buttonStyle(.plain)
            .onHover { h in btnHovered = h }
            .opacity(appeared ? 1 : 0)
            .animation(.easeOut(duration: 0.5).delay(0.28), value: appeared)

            // ── Feature cards ─────────────────────────────────────────────
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                FeatureCard(emoji: "🔒", title: "85 Security Checks", subtitle: "Full CIS Benchmark coverage")
                FeatureCard(emoji: "⚡", title: "Auto-Fix", subtitle: "One-tap remediation for issues")
                FeatureCard(emoji: "🔍", title: "Deep Analysis", subtitle: "Network, privacy & system settings")
                FeatureCard(emoji: "📋", title: "Audit Reports", subtitle: "Export to HTML or JSON")
            }
            .frame(maxWidth: 480)
            .opacity(appeared ? 1 : 0)
            .animation(.easeOut(duration: 0.5).delay(0.40), value: appeared)

            Spacer(minLength: 0)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { appeared = true }
    }
}

struct FeatureCard: View {
    let emoji: String
    let title: String
    let subtitle: String

    @State private var hovered = false

    var body: some View {
        HStack(spacing: 12) {
            Text(emoji)
                .font(.system(size: 20))
                .frame(width: 34, height: 34)
                .background(Color(NSColor.windowBackgroundColor))
                .cornerRadius(8)
                .shadow(color: .black.opacity(0.06), radius: 2, y: 1)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(NSColor.windowBackgroundColor))
                .shadow(color: .black.opacity(hovered ? 0.10 : 0.05), radius: hovered ? 8 : 4, y: 2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(NSColor.separatorColor).opacity(0.6), lineWidth: 1)
        )
        .scaleEffect(hovered ? 1.02 : 1.0)
        .animation(.easeInOut(duration: 0.15), value: hovered)
        .onHover { h in hovered = h }
    }
}


struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
