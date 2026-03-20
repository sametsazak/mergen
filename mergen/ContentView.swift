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

                    Rectangle()
                        .fill(Color.white.opacity(0.08))
                        .frame(height: 1)

                    HStack(spacing: 0) {
                        ResultsListView(
                            scanManager: scanManager,
                            selectedCategory: nil,
                            selectedVulnerability: $selectedVulnerability,
                            searchText: $searchText
                        )
                        .frame(minWidth: 300, idealWidth: 380)

                        Rectangle()
                            .fill(Color.white.opacity(0.08))
                            .frame(width: 1)

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
        .background(
            LinearGradient(
                colors: [
                    Color(red: 0.12, green: 0.08, blue: 0.26),
                    Color(red: 0.22, green: 0.15, blue: 0.42),
                    Color(red: 0.34, green: 0.26, blue: 0.60),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
        )
        .preferredColorScheme(.dark)
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

    private let accent = Color(red: 0.65, green: 0.52, blue: 1.00)
    private let accentDp = Color(red: 0.42, green: 0.26, blue: 0.88)

    private var automated: [Vulnerability] { scanManager.scanResults.filter { !$0.isManual && $0.checkstatus != "Blue" } }
    private var passCount: Int { automated.filter { $0.checkstatus == "Green" }.count }
    private var failCount: Int { scanManager.scanResults.filter { $0.checkstatus == "Red" }.count }
    private var warnCount: Int { scanManager.scanResults.filter { $0.checkstatus == "Yellow" }.count }
    private var score:     Double { automated.isEmpty ? 0 : Double(passCount) / Double(automated.count) }
    private var fixable:   Int { scanManager.scanResults.filter { $0.isAutoFixable }.count }

    private var scoreColor: Color {
        score >= 0.8 ? Color(red: 0.13, green: 0.83, blue: 0.60)
            : score >= 0.5 ? Color(red: 0.97, green: 0.73, blue: 0.32)
            : Color(red: 1.00, green: 0.45, blue: 0.45)
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
                        colors: [accent, accentDp],
                        startPoint: .top, endPoint: .bottom
                    ))
                Text("Mergen")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
            }
            .padding(.horizontal, 16)

            divider()

            // ── Score ring ─────────────────────────────────────────────────
            HStack(spacing: 8) {
                ZStack {
                    Circle()
                        .stroke(Color.white.opacity(0.12), lineWidth: 3)
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
                        .foregroundColor(.white.opacity(0.45))
                        .tracking(0.6)
                }
            }
            .padding(.horizontal, 14)

            divider()

            // ── Stats ──────────────────────────────────────────────────────
            HStack(spacing: 20) {
                statChip(passCount, "Passed",   Color(red: 0.13, green: 0.83, blue: 0.60))
                statChip(failCount, "Failed",   Color(red: 1.00, green: 0.45, blue: 0.45))
                statChip(warnCount, "Warnings", Color(red: 0.97, green: 0.73, blue: 0.32))
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
                        .foregroundColor(.white.opacity(0.65))
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
                        .tint(Color(red: 1.00, green: 0.35, blue: 0.35))
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
        .background(Color(red: 0.10, green: 0.07, blue: 0.20).opacity(0.85))
    }

    @ViewBuilder
    private func divider() -> some View {
        Rectangle()
            .fill(Color.white.opacity(0.10))
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
                .foregroundColor(.white.opacity(0.50))
        }
    }
}

// MARK: - Welcome View

struct WelcomeView: View {
    let onScan: () -> Void

    @State private var pulse1     = false
    @State private var pulse2     = false
    @State private var glowing    = false
    @State private var appeared   = false
    @State private var btnHovered = false

    var body: some View {
        VStack(spacing: 28) {
            Spacer()

            // ── Hero ──────────────────────────────────────────────────────
            ZStack {
                // Outer pulse ring
                Circle()
                    .stroke(Color.white.opacity(pulse2 ? 0 : 0.07), lineWidth: 1.5)
                    .frame(width: 240, height: 240)
                    .scaleEffect(pulse2 ? 1.45 : 1.0)
                    .animation(.easeOut(duration: 2.6).repeatForever(autoreverses: false), value: pulse2)

                // Inner pulse ring
                Circle()
                    .stroke(Color.white.opacity(pulse1 ? 0 : 0.14), lineWidth: 1.5)
                    .frame(width: 180, height: 180)
                    .scaleEffect(pulse1 ? 1.38 : 1.0)
                    .animation(.easeOut(duration: 2.6).repeatForever(autoreverses: false), value: pulse1)

                // Glow bloom
                Circle()
                    .fill(Color(red: 0.56, green: 0.40, blue: 0.95).opacity(glowing ? 0.40 : 0.18))
                    .frame(width: 130, height: 130)
                    .blur(radius: 28)
                    .animation(.easeInOut(duration: 3.0).repeatForever(autoreverses: true), value: glowing)

                // Shield icon
                Image(systemName: "shield.fill")
                    .font(.system(size: 82))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [
                                Color(red: 0.82, green: 0.70, blue: 1.00),
                                Color(red: 0.55, green: 0.36, blue: 0.94),
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .shadow(
                        color: Color(red: 0.55, green: 0.36, blue: 0.94).opacity(glowing ? 0.65 : 0.30),
                        radius: glowing ? 30 : 14
                    )
                    .animation(.easeInOut(duration: 3.0).repeatForever(autoreverses: true), value: glowing)
            }
            .frame(width: 250, height: 250)
            .scaleEffect(appeared ? 1.0 : 0.72)
            .opacity(appeared ? 1 : 0)
            .animation(.spring(response: 0.68, dampingFraction: 0.72), value: appeared)
            .onAppear {
                glowing = true
                pulse1  = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { pulse2 = true }
            }

            // ── Title ─────────────────────────────────────────────────────
            VStack(spacing: 8) {
                Text("Welcome to Mergen")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                Text("Start with a thorough security audit of your Mac.")
                    .font(.system(size: 14))
                    .foregroundColor(.white.opacity(0.58))
                    .multilineTextAlignment(.center)
            }
            .opacity(appeared ? 1 : 0)
            .offset(y: appeared ? 0 : 12)
            .animation(.easeOut(duration: 0.5).delay(0.15), value: appeared)

            // ── Circular scan button ──────────────────────────────────────
            Button(action: onScan) {
                ZStack {
                    Circle()
                        .stroke(Color.white.opacity(0.20), lineWidth: 1.5)
                        .frame(width: btnHovered ? 90 : 84, height: btnHovered ? 90 : 84)
                        .animation(.spring(response: 0.3, dampingFraction: 0.65), value: btnHovered)

                    Circle()
                        .fill(
                            LinearGradient(
                                colors: [
                                    Color(red: 0.65, green: 0.52, blue: 1.00),
                                    Color(red: 0.42, green: 0.26, blue: 0.88),
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 74, height: 74)
                        .shadow(
                            color: Color(red: 0.48, green: 0.32, blue: 0.90).opacity(btnHovered ? 0.62 : 0.38),
                            radius: btnHovered ? 22 : 12
                        )
                        .animation(.spring(response: 0.3, dampingFraction: 0.65), value: btnHovered)

                    Text("Scan")
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .foregroundColor(.white)
                }
            }
            .buttonStyle(.plain)
            .scaleEffect(btnHovered ? 1.06 : 1.0)
            .animation(.spring(response: 0.3, dampingFraction: 0.65), value: btnHovered)
            .onHover { h in btnHovered = h }
            .opacity(appeared ? 1 : 0)
            .animation(.easeOut(duration: 0.5).delay(0.28), value: appeared)

            // ── Stats strip ───────────────────────────────────────────────
            HStack(spacing: 0) {
                WelcomeStatPill(value: "85", label: "checks")
                Rectangle().fill(Color.white.opacity(0.12)).frame(width: 1, height: 28)
                WelcomeStatPill(value: "42", label: "auto-fixable")
                Rectangle().fill(Color.white.opacity(0.12)).frame(width: 1, height: 28)
                WelcomeStatPill(value: "6", label: "sections")
            }
            .background(Color.white.opacity(0.06))
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.white.opacity(0.10), lineWidth: 1)
            )
            .opacity(appeared ? 1 : 0)
            .animation(.easeOut(duration: 0.5).delay(0.40), value: appeared)

            Spacer()
        }
        .padding(36)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { appeared = true }
    }
}

struct WelcomeStatPill: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 17, weight: .bold, design: .rounded))
                .foregroundColor(.white)
            Text(label)
                .font(.caption2)
                .foregroundColor(.white.opacity(0.52))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
    }
}

// MARK: - Color Extensions

extension Color {
    static let gradient = Color("Gradient")
    static let gradient2 = Color("Gradient2")
    static let gradient3 = Color("Gradient3")
    static let buttoncolor = Color("buttoncolor")
    static let buttonhover = Color("buttonhover")
    static let detailcolor = Color("detail")
    static let buttoncenter = Color("buttoncenter")
    static let welcomecolor = Color("welcome")
    static let fontcolor = Color("fontcolor")
    static let grayish = Color("grayish")
    static let toolcolor = Color("toolcolor")
    static let welcometext = Color("welcometext")
    static let framebackground = Color("framebackground")
    static let scanresultcolor = Color("scanresult")
    static let progresscolor = Color("progresscolor")
    static let yellown = Color("yellown")
    static let buttongradient1 = Color("buttongradient1")
    static let buttongradient2 = Color("buttongradient2")
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
