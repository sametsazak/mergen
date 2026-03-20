//
//  SidebarView.swift
//  mergen
//

import SwiftUI

struct SidebarView: View {
    @ObservedObject var scanManager: ScanManager
    @Binding var selectedCategory: String?
    @State private var showFixSheet = false

    private let categories: [(label: String, icon: String, value: String?, color: Color)] = [
        ("All Checks",    "shield.lefthalf.filled",  nil,             Color(red: 0.39, green: 0.40, blue: 0.95)),
        ("CIS Benchmark", "lock.laptopcomputer",      "CIS Benchmark", Color(red: 0.13, green: 0.73, blue: 0.54)),
        ("Privacy",       "eye.slash",                "Privacy",       Color(red: 0.98, green: 0.63, blue: 0.22)),
        ("Security",      "lock.shield",              "Security",      Color(red: 0.96, green: 0.36, blue: 0.36)),
    ]

    var body: some View {
        VStack(spacing: 0) {

            // ── Branding ───────────────────────────────────────────────────
            VStack(spacing: 6) {
                ZStack {
                    Circle()
                        .fill(Color.accentColor.opacity(0.12))
                        .frame(width: 56, height: 56)
                    Image(systemName: "shield.fill")
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 28, height: 28)
                        .foregroundStyle(
                            LinearGradient(
                                colors: [.accentColor, .accentColor.opacity(0.65)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .shadow(color: .accentColor.opacity(0.35), radius: 6, y: 2)
                }

                VStack(spacing: 2) {
                    Text("Mergen")
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                    Text("macOS Security Audit")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.top, 24)
            .padding(.bottom, 18)

            // ── Navigation ─────────────────────────────────────────────────
            VStack(spacing: 3) {
                ForEach(categories, id: \.label) { cat in
                    CategoryRow(
                        label: cat.label,
                        icon: cat.icon,
                        iconColor: cat.color,
                        isSelected: selectedCategory == cat.value,
                        isDisabled: scanManager.scanning
                    ) {
                        selectedCategory = cat.value
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.bottom, 14)

            Divider().padding(.horizontal, 14)

            // ── Scan controls ──────────────────────────────────────────────
            VStack(spacing: 8) {
                if scanManager.scanning {
                    VStack(spacing: 10) {
                        CircularProgressView(progress: scanManager.progress)
                        VStack(spacing: 2) {
                            Text("\(Int(scanManager.progress * 100))%")
                                .font(.system(size: 13, weight: .bold, design: .rounded))
                                .foregroundColor(.accentColor)
                            Text("\(scanManager.scanResults.count) checks done")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 14)
                } else {
                    Button(action: {
                        scanManager.startScan(category: selectedCategory)
                    }) {
                        Label("Start Scan", systemImage: "play.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(PrimaryButtonStyle())

                    if !scanManager.scanResults.isEmpty {
                        let fixableCount = scanManager.scanResults.filter { $0.isAutoFixable }.count

                        if fixableCount > 0 {
                            Button(action: { showFixSheet = true }) {
                                Label("Fix \(fixableCount) Issue\(fixableCount == 1 ? "" : "s")",
                                      systemImage: "bolt.fill")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(FixButtonStyle())
                            .sheet(isPresented: $showFixSheet) {
                                FixAllSheet(scanManager: scanManager)
                            }
                        }

                        Button(action: { scanManager.resetScan() }) {
                            Label("Reset", systemImage: "arrow.counterclockwise")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(SecondaryButtonStyle())
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.top, 14)

            // ── Score (after scan) ──────────────────────────────────────────
            if !scanManager.scanResults.isEmpty && !scanManager.scanning {
                SecurityScoreView(scanResults: scanManager.scanResults)
                    .padding(.horizontal, 10)
                    .padding(.top, 8)
                    .transition(.opacity.combined(with: .move(edge: .bottom)))
            }

            Spacer()
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }
}

// MARK: - Category Row

struct CategoryRow: View {
    let label: String
    let icon: String
    let iconColor: Color
    let isSelected: Bool
    let isDisabled: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 6)
                        .fill(isSelected ? iconColor.opacity(0.15) : Color.primary.opacity(0.06))
                        .frame(width: 26, height: 26)
                    Image(systemName: icon)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(isSelected ? iconColor : .secondary)
                }
                Text(label)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .regular))
                    .foregroundColor(isSelected ? .primary : .secondary)
                Spacer()
                if isSelected {
                    Circle()
                        .fill(iconColor)
                        .frame(width: 6, height: 6)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(isSelected
                          ? iconColor.opacity(0.09)
                          : (isHovered ? Color.primary.opacity(0.04) : Color.clear))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? iconColor.opacity(0.22) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .onHover { h in withAnimation(.easeInOut(duration: 0.1)) { isHovered = h } }
    }
}

// MARK: - Button Styles

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .padding(.vertical, 9)
            .padding(.horizontal, 14)
            .background(
                LinearGradient(
                    colors: [
                        Color(red: 0.39, green: 0.44, blue: 0.98),
                        Color(red: 0.52, green: 0.34, blue: 0.96)
                    ],
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .foregroundColor(.white)
            .cornerRadius(10)
            .shadow(color: Color(red: 0.39, green: 0.40, blue: 0.95).opacity(0.35), radius: 6, y: 3)
            .opacity(configuration.isPressed ? 0.88 : 1.0)
            .scaleEffect(configuration.isPressed ? 0.98 : 1.0)
    }
}

struct FixButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .padding(.vertical, 9)
            .padding(.horizontal, 14)
            .background(
                LinearGradient(
                    colors: [
                        Color(red: 0.96, green: 0.28, blue: 0.28),
                        Color(red: 0.83, green: 0.17, blue: 0.37)
                    ],
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .foregroundColor(.white)
            .cornerRadius(10)
            .shadow(color: Color.red.opacity(0.30), radius: 6, y: 3)
            .opacity(configuration.isPressed ? 0.88 : 1.0)
            .scaleEffect(configuration.isPressed ? 0.98 : 1.0)
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .padding(.vertical, 8)
            .padding(.horizontal, 14)
            .background(Color.primary.opacity(0.07))
            .foregroundColor(.secondary)
            .cornerRadius(10)
            .opacity(configuration.isPressed ? 0.7 : 1.0)
    }
}
