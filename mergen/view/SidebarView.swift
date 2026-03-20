//
//  SidebarView.swift
//  mergen
//

import SwiftUI

struct SidebarView: View {
    @ObservedObject var scanManager: ScanManager
    @Binding var selectedCategory: String?
    @State private var isScanButtonHovered = false
    @State private var showFixSheet = false

    private let categories: [(label: String, icon: String, value: String?)] = [
        ("All Checks",    "shield.lefthalf.filled",  nil),
        ("CIS Benchmark", "lock.laptopcomputer",      "CIS Benchmark"),
        ("Privacy",       "eye.slash",                "Privacy"),
        ("Security",      "lock.shield",              "Security"),
    ]

    var body: some View {
        VStack(spacing: 0) {

            // Branding
            VStack(spacing: 4) {
                Image(systemName: "shield.lefthalf.filled.slash")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 38, height: 38)
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.accentColor, .accentColor.opacity(0.6)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                Text("Mergen")
                    .font(.system(size: 19, weight: .bold, design: .rounded))
                Text("macOS Security Audit")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.top, 22)
            .padding(.bottom, 16)

            // Category list
            VStack(spacing: 2) {
                ForEach(categories, id: \.label) { cat in
                    CategoryRow(
                        label: cat.label,
                        icon: cat.icon,
                        isSelected: selectedCategory == cat.value,
                        isDisabled: scanManager.scanning
                    ) {
                        selectedCategory = cat.value
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.top, 6)
            .padding(.bottom, 10)

            // Scan controls
            VStack(spacing: 10) {
                if scanManager.scanning {
                    VStack(spacing: 8) {
                        CircularProgressView(progress: scanManager.progress)
                        Text("\(scanManager.scanResults.count) checks completed")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                        Text("\(Int(scanManager.progress * 100))%")
                            .font(.system(size: 11, weight: .semibold, design: .rounded))
                            .foregroundColor(.accentColor)
                    }
                    .padding(.vertical, 12)
                } else {
                    Button(action: {
                        scanManager.startScan(category: selectedCategory)
                    }) {
                        Label("Start Scan", systemImage: "play.circle.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .scaleEffect(isScanButtonHovered ? 1.02 : 1.0)
                    .onHover { h in
                        withAnimation(.easeInOut(duration: 0.15)) { isScanButtonHovered = h }
                    }

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
            .padding(.vertical, 12)

            // Security score (shown after scan)
            if !scanManager.scanResults.isEmpty && !scanManager.scanning {
                SecurityScoreView(scanResults: scanManager.scanResults)
                    .padding(.horizontal, 12)
                    .padding(.top, 4)
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
    let isSelected: Bool
    let isDisabled: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .frame(width: 20)
                    .foregroundColor(isSelected ? .accentColor : .secondary)
                Text(label)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .regular))
                    .foregroundColor(isSelected ? .primary : .secondary)
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 7)
                    .fill(isSelected
                          ? Color.accentColor.opacity(0.12)
                          : (isHovered ? Color.primary.opacity(0.05) : Color.clear))
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
            .padding(.vertical, 8)
            .padding(.horizontal, 14)
            .background(Color.accentColor)
            .foregroundColor(.white)
            .cornerRadius(9)
            .opacity(configuration.isPressed ? 0.85 : 1.0)
    }
}

struct FixButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .padding(.vertical, 8)
            .padding(.horizontal, 14)
            .background(Color.red.opacity(0.88))
            .foregroundColor(.white)
            .cornerRadius(9)
            .opacity(configuration.isPressed ? 0.85 : 1.0)
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13))
            .padding(.vertical, 7)
            .padding(.horizontal, 14)
            .background(Color.primary.opacity(0.07))
            .foregroundColor(.primary)
            .cornerRadius(9)
            .opacity(configuration.isPressed ? 0.7 : 1.0)
    }
}
