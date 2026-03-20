//
//  SecurityScoreView.swift
//  mergen
//
//  Speedometer gauge + per-section pass bars shown in the sidebar after a scan.
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
        score >= 0.8 ? .green : score >= 0.5 ? .orange : .red
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
        VStack(spacing: 10) {

            SpeedometerView(score: score, scoreColor: scoreColor, scoreLabel: scoreLabel)

            if !sections.isEmpty {
                VStack(spacing: 6) {
                    ForEach(sections, id: \.name) { sec in
                        SectionBarRow(name: sec.name, pass: sec.pass, total: sec.total)
                    }
                }
                .padding(.horizontal, 2)
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
        .padding(.vertical, 8)
    }
}

// MARK: - Speedometer Gauge

struct SpeedometerView: View {
    let score:      Double
    let scoreColor: Color
    let scoreLabel: String

    var body: some View {
        Color.clear
            .frame(height: 100)
            .overlay(
                GeometryReader { geo in
                    SpeedometerCanvas(
                        score:      score,
                        scoreColor: scoreColor,
                        scoreLabel: scoreLabel,
                        size:       geo.size
                    )
                }
            )
    }
}

private struct SpeedometerCanvas: View {
    let score:      Double
    let scoreColor: Color
    let scoreLabel: String
    let size:       CGSize

    private var cx: CGFloat { size.width / 2 }
    private var cy: CGFloat { size.height }
    private var r:  CGFloat { min(size.width / 2 - 10, size.height - 8) }
    private var lw: CGFloat { 9 }

    // needle angle: 180° = left (0%), 270° = up (50%), 360° = right (100%)
    private var needleRad: Double { (180.0 + score * 180.0) * .pi / 180.0 }

    var body: some View {
        ZStack {
            gaugeBackground
            progressArc
            needle
            pivotDot
            scoreLabel_view
        }
        .clipped()
    }

    // MARK: Sub-views (split to help the type checker)

    private var gaugeBackground: some View {
        ZStack {
            // Red zone 180→240
            arcStroke(from: 180, to: 240, color: Color.red.opacity(0.15), cap: .butt)
            // Orange zone 240→300
            arcStroke(from: 240, to: 300, color: Color.orange.opacity(0.13), cap: .butt)
            // Green zone 300→360
            arcStroke(from: 300, to: 360, color: Color.green.opacity(0.13), cap: .butt)
            // Gray track overlay
            arcStroke(from: 180, to: 360, color: Color.primary.opacity(0.07), cap: .butt)
        }
    }

    private var progressArc: some View {
        arcStroke(from: 180, to: 180 + score * 180, color: scoreColor, cap: .round)
            .animation(.easeInOut(duration: 0.9), value: score)
    }

    private var needleTip: CGPoint {
        let nLen = r * 0.66
        return CGPoint(x: cx + nLen * CGFloat(Foundation.cos(needleRad)),
                       y: cy + nLen * CGFloat(Foundation.sin(needleRad)))
    }

    private var needle: some View {
        let tip = needleTip
        let pivot = CGPoint(x: cx, y: cy)
        return Path { p in
            p.move(to: pivot)
            p.addLine(to: tip)
        }
        .stroke(Color.primary.opacity(0.6),
                style: StrokeStyle(lineWidth: 1.5, lineCap: .round))
        .animation(.easeInOut(duration: 0.9), value: score)
    }

    private var pivotDot: some View {
        Circle()
            .fill(Color.primary.opacity(0.2))
            .frame(width: 8, height: 8)
            .position(x: cx, y: cy)
    }

    private var scoreLabel_view: some View {
        VStack(spacing: 1) {
            Text("\(Int(score * 100))%")
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundColor(scoreColor)
            Text(scoreLabel.uppercased())
                .font(.system(size: 8, weight: .semibold, design: .rounded))
                .foregroundColor(.secondary)
                .tracking(0.6)
        }
        .position(x: cx, y: cy - r * 0.50)
    }

    // MARK: Helper

    private func arcStroke(from: Double, to: Double, color: Color, cap: CGLineCap) -> some View {
        Path { p in
            p.addArc(center: .init(x: cx, y: cy), radius: r,
                     startAngle: .degrees(from), endAngle: .degrees(to), clockwise: true)
        }
        .stroke(color, style: StrokeStyle(lineWidth: lw, lineCap: cap))
    }
}

// MARK: - Section Pass Bar

struct SectionBarRow: View {
    let name:  String
    let pass:  Int
    let total: Int

    private var ratio:    Double { total > 0 ? Double(pass) / Double(total) : 0 }
    private var barColor: Color  { ratio >= 0.8 ? .green : ratio >= 0.5 ? .orange : .red }

    var body: some View {
        HStack(spacing: 6) {
            Text(name)
                .font(.system(size: 9, weight: .medium, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 62, alignment: .leading)
                .lineLimit(1)

            GeometryReader { g in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color.primary.opacity(0.07))
                    RoundedRectangle(cornerRadius: 3)
                        .fill(barColor.opacity(0.72))
                        .frame(width: max(0, g.size.width * ratio))
                        .animation(.easeInOut(duration: 0.6).delay(0.05), value: ratio)
                }
            }
            .frame(height: 5)

            Text("\(pass)/\(total)")
                .font(.system(size: 8, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 24, alignment: .trailing)
        }
    }
}
