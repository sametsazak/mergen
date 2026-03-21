//
//  FixAllSheet.swift
//  mergen
//
//  Sheet showing all auto-fixable failed checks with individual and batch
//  apply buttons.
//

import SwiftUI

struct FixAllSheet: View {
    @ObservedObject var scanManager: ScanManager
    @Environment(\.dismiss) private var dismiss
    @State private var showLog = false

    private var fixable: [Vulnerability] {
        scanManager.scanResults.filter { $0.isAutoFixable }
    }

    private var adminCount:   Int  { fixable.filter {  $0.fixRequiresAdmin }.count }
    private var userCount:    Int  { fixable.filter { !$0.fixRequiresAdmin }.count }
    private var isFixing:     Bool { !scanManager.fixingIDs.isEmpty }
    private var hasFailures:  Bool { scanManager.fixResults.values.contains(false) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {

            // ── Header ──────────────────────────────────────────────────────
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Fix All Issues")
                        .font(.system(size: 18, weight: .bold))
                    Text("\(fixable.count) issue\(fixable.count == 1 ? "" : "s") can be fixed automatically")
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

            // ── Admin privilege notice ───────────────────────────────────────
            if adminCount > 0 {
                let adminColor = Color(red: 0.97, green: 0.63, blue: 0.22)
                HStack(spacing: 0) {
                    RoundedRectangle(cornerRadius: 0)
                        .fill(adminColor)
                        .frame(width: 4)
                    HStack(spacing: 12) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 20))
                            .foregroundColor(adminColor)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(adminCount) fix\(adminCount == 1 ? "" : "es") require administrator privileges")
                                .font(.system(size: 13, weight: .semibold))
                            Text("You will be prompted once for your password. All admin fixes are batched together.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(adminColor.opacity(0.08))
                Divider()
            }

            // ── List ─────────────────────────────────────────────────────────
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(fixable, id: \.id) { v in
                        FixRowItem(vulnerability: v, scanManager: scanManager)
                        Divider().padding(.leading, 48)
                    }
                }
            }

            Divider()

            // ── Footer ───────────────────────────────────────────────────────
            HStack(spacing: 10) {
                if isFixing {
                    Label("Applying fixes…", systemImage: "gearshape.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                } else if hasFailures {
                    Button {
                        showLog = true
                    } label: {
                        Label("View Audit Log", systemImage: "doc.text.magnifyingglass")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                Spacer()
                Button("Close") { dismiss() }
                    .buttonStyle(.bordered)
                if !isFixing {
                    Button {
                        scanManager.fixAll(fixable)
                    } label: {
                        Label("Apply All Fixes", systemImage: "bolt.fill")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
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
                            .cornerRadius(9)
                            .shadow(color: Color.accentColor.opacity(0.30), radius: 5, y: 2)
                    }
                    .buttonStyle(.plain)
                    .disabled(fixable.isEmpty)
                    .opacity(fixable.isEmpty ? 0.5 : 1)
                }
            }
            .padding(16)
        }
        .frame(width: 560, height: 500)
        .sheet(isPresented: $showLog) {
            LogViewerSheet()
        }
    }
}

// MARK: - Fix Row

struct FixRowItem: View {
    let vulnerability: Vulnerability
    @ObservedObject var scanManager: ScanManager

    private var isFixing:   Bool  { scanManager.fixingIDs.contains(vulnerability.id) }
    private var result:     Bool? { scanManager.fixResults[vulnerability.id] }
    private var isFixed:    Bool  { vulnerability.checkstatus == "Green" }
    private var isCancelled: Bool { scanManager.fixCancelled.contains(vulnerability.id) }

    private var rowIcon: String {
        if isFixed            { return "checkmark.circle.fill" }
        if let r = result     { return r ? "checkmark.circle.fill" : "xmark.circle.fill" }
        return "xmark.circle.fill"
    }

    private var rowColor: Color {
        if isFixed            { return .green }
        if let r = result     { return r ? .green : .red }
        return .red
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: rowIcon)
                .foregroundColor(rowColor)
                .font(.system(size: 16))
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 4) {
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

                // Before: current finding
                if let current = vulnerability.status, !current.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.right.circle")
                            .font(.system(size: 9))
                            .foregroundColor(.red.opacity(0.7))
                        Text("Now: \(current)")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }

                // After: what changes
                if let after = vulnerability.fixDescription {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.circle")
                            .font(.system(size: 9))
                            .foregroundColor(.green.opacity(0.8))
                        Text("Fix: \(after)")
                            .font(.system(size: 10))
                            .foregroundColor(.green.opacity(0.85))
                            .lineLimit(2)
                    }
                }

                if vulnerability.fixRequiresAdmin {
                    Label("Requires admin", systemImage: "lock.fill")
                        .font(.system(size: 9))
                        .foregroundColor(.orange)
                }
            }

            Spacer()

            // Action area
            Group {
                if isFixing {
                    ProgressView()
                        .scaleEffect(0.75)
                        .frame(width: 64)
                } else if isFixed {
                    Text("Fixed ✓")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.green)
                } else if isCancelled {
                    Text("Cancelled")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                } else if let r = result, !r {
                    VStack(alignment: .trailing, spacing: 2) {
                        Label("Still failing", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(.red)
                        if let status = vulnerability.status, !status.isEmpty {
                            Text(status)
                                .font(.system(size: 9))
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.trailing)
                                .lineLimit(2)
                        }
                    }
                } else {
                    Button("Fix") {
                        scanManager.applyFix(for: vulnerability)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .tint(.accentColor)
                }
            }
            .frame(minWidth: 64, alignment: .trailing)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .animation(.default, value: isFixing)
        .animation(.default, value: isFixed)
    }
}
