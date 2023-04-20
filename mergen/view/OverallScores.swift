//
//  OverallScores.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import SwiftUI


struct ScanResultIndicator: View {
    let scanResults: [Vulnerability]
    private var groupedScanResults: [String: [Vulnerability]] {
        Dictionary(grouping: scanResults, by: { $0.checkstatus! })
    }

    var body: some View {
        HStack {
            ScanResultSegment(iconName: "checkmark.circle.fill", label: "Passed", count: groupedScanResults["Green"]?.count ?? 0, color: .green)
            ScanResultSegment(iconName: "exclamationmark.circle.fill", label: "Failed", count: groupedScanResults["Red"]?.count ?? 0, color: .red)
            ScanResultSegment(iconName: "questionmark.circle.fill", label: "Unknown", count: groupedScanResults["Yellow"]?.count ?? 0, color: .yellow)
        }
    }
}

struct ScanResultSegment: View {
    let iconName: String
    let label: String
    let count: Int
    let color: Color

    var body: some View {
        VStack {
            Image(systemName: iconName)
                .resizable()
                .frame(width: 30, height: 30)
                .foregroundColor(color)
            Text(label)
                .font(.title3)
                .foregroundColor(.accentColor)
            Text(String(count))
                .font(.title3)
                .foregroundColor(.accentColor)
        }
        .padding(.bottom, 0)
        .frame(minWidth: 100, minHeight: 100) // Adding fixed frame
        .background(Color.grayish.opacity(0.5))
    }
}

