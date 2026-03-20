//
//  SecurityScoreView.swift
//  mergen
//
//  Circular score ring + per-section pass bars shown in the sidebar after a scan.
//

import SwiftUI

// MARK: - Top-level container

struct SecurityScoreView: View {
    let scanResults: [Vulnerability]

    private var automated:   [Vulnerability] { scanResults.filter { !$0.isManual } }
    private var greenCount:  Int { automated.filter { $0.checkstatus == "Green"  }.count }
    private var redCount:    Int { automated.filter { $0.checkstatus == "Red"    }.count }
    private var yellowCount: Int { automated.filter { $0.checkstatus == "Yellow" }.count }
    private var manualCount: Int { scanResults.filter { $0.isManual || $0.checkstatus == "Blue" }.count }
    private var total:       Int { greenCount + redCount + yellowCount }
    private var score:       Double { total > 0 ? Double(greenCount) / Double(total) : 0 }

    private var scoreColor: Color {
        score >= 0.8 ? Color(red: 0.13, green: 0.73, blue: 0.54)
            : score >= 0.5 ? Color(red: 0.97, green: 0.63, blue: 0.22)
            : Color(red: 0.96, green: 0.36, blue: 0.36)
    }
    private var scoreLabel: String {
        score >= 0.8 ? "Good" : score >= 0.5 ? "Fair" : "At Risk"
    }

    private var sections: [(name: String, pass: Int, total: Int)] {
        let defs: [(String, String)] = [
            ("§1 Updates",  "1"),
            ("§2 Settings", "2"),
            ("§3 Logging",  "3"),
            ("§4 Network",  "4"),
            ("§5 Auth",     "5"),
            ("§6 UI",       "6"),
        ]
        return defs.compactMap { (name, prefix) in
            let items = automated.filter {
                !$0.cisID.isEmpty &&
                ($0.cisID.split(separator: ".").first.map(String.init) ?? "") == prefix
            }
            guard !items.isEmpty else { return nil }
            return (name, items.filter { $0.checkstatus == "Green" }.count, items.count)
        }
    }

    var body: some View {
        VStack(spacing: 12) {

            // ── Circular score ring ────────────────────────────────────────
            CircularScoreRing(score: score, scoreColor: scoreColor, scoreLabel: scoreLabel)

            // ── Stat pills ─────────────────────────────────────────────────
            HStack(spacing: 0) {
                ScorePill(value: greenCount,  label: "Pass",  color: Color(red: 0.13, green: 0.73, blue: 0.54))
                ScorePill(value: redCount,    label: "Fail",  color: Color(red: 0.96, green: 0.36, blue: 0.36))
                ScorePill(value: yellowCount, label: "Warn",  color: Color(red: 0.97, green: 0.63, blue: 0.22))
            }
            .background(Color.primary.opacity(0.04))
            .cornerRadius(8)
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.primary.opacity(0.07), lineWidth: 1))

            // ── Section bars ────────────────────────────────────────────────
            if !sections.isEmpty {
                VStack(spacing: 5) {
                    ForEach(sections, id: \.name) { sec in
                        SectionBarRow(name: sec.name, pass: sec.pass, total: sec.total)
                    }
                }
            }

            if manualCount > 0 {
                HStack(spacing: 4) {
                    Image(systemName: "info.circle.fill")
                        .font(.caption2)
                        .foregroundColor(.blue)
                    Text("\(manualCount) need manual review")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.vertical, 10)
    }
}

// MARK: - Circular Score Ring

struct CircularScoreRing: View {
    let score: Double
    let scoreColor: Color
    let scoreLabel: String

    @State private var animatedScore: Double = 0

    private let ringSize: CGFloat  = 106
    private let lineWidth: CGFloat = 11

    var body: some View {
        ZStack {
            // Track
            Circle()
                .stroke(Color.primary.opacity(0.08), lineWidth: lineWidth)
                .frame(width: ringSize, height: ringSize)

            // Colored arc
            Circle()
                .trim(from: 0, to: animatedScore)
                .stroke(
                    AngularGradient(
                        colors: [scoreColor.opacity(0.75), scoreColor],
                        center: .center,
                        startAngle: .degrees(-90),
                        endAngle: .degrees(360 * animatedScore - 90)
                    ),
                    style: StrokeStyle(lineWidth: lineWidth, lineCap: .round)
                )
                .frame(width: ringSize, height: ringSize)
                .rotationEffect(.degrees(-90))
                .animation(.spring(response: 1.1, dampingFraction: 0.82), value: animatedScore)

            // Center
            VStack(spacing: 0) {
                Text("\(Int(score * 100))%")
                    .font(.system(size: 21, weight: .bold, design: .rounded))
                    .foregroundColor(scoreColor)
                    .animation(.easeInOut(duration: 0.9), value: score)
                Text(scoreLabel.uppercased())
                    .font(.system(size: 8, weight: .semibold, design: .rounded))
                    .foregroundColor(.secondary)
                    .tracking(0.7)
            }
        }
        .frame(width: ringSize, height: ringSize)
        .onAppear { animatedScore = score }
        .onChange(of: score) { newVal in animatedScore = newVal }
    }
}

// MARK: - Score Pill

struct ScorePill: View {
    let value: Int
    let label: String
    let color: Color

    var body: some View {
        VStack(spacing: 1) {
            Text("\(value)")
                .font(.system(size: 14, weight: .bold, design: .rounded))
                .foregroundColor(color)
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 7)
    }
}

// MARK: - Section Bar Row

struct SectionBarRow: View {
    let name:  String
    let pass:  Int
    let total: Int

    private var ratio:    Double { total > 0 ? Double(pass) / Double(total) : 0 }
    private var barColor: Color  {
        ratio >= 0.8
            ? Color(red: 0.13, green: 0.73, blue: 0.54)
            : ratio >= 0.5
                ? Color(red: 0.97, green: 0.63, blue: 0.22)
                : Color(red: 0.96, green: 0.36, blue: 0.36)
    }

    var body: some View {
        HStack(spacing: 6) {
            Text(name)
                .font(.system(size: 9, weight: .medium, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 62, alignment: .leading)
                .lineLimit(1)

            GeometryReader { g in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.primary.opacity(0.07))
                    RoundedRectangle(cornerRadius: 4)
                        .fill(barColor)
                        .frame(width: max(0, g.size.width * ratio))
                        .animation(.spring(response: 0.8, dampingFraction: 0.82).delay(0.1), value: ratio)
                }
            }
            .frame(height: 6)

            Text("\(pass)/\(total)")
                .font(.system(size: 8, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 24, alignment: .trailing)
        }
    }
}
