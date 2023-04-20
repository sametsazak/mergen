//
//  ScanButton.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import SwiftUI

struct ScanButton: View {
    @ObservedObject var scanManager: ScanManager
    @Binding var showScanResults: Bool
    @Binding var selectedCat: String
    @State private var isHovered = false
    
    var body: some View {
        ZStack {
            Button(action: {
                if !scanManager.scanning {
                    startScanAndShowResults()
                }
            }) {
                Image(systemName: "magnifyingglass.circle.fill")
                    .resizable()
                    .frame(width: 70, height: 70)
                    .foregroundColor(.accentColor)
            }
            .buttonStyle(PlainButtonStyle())
            .frame(width: 100, height: 100)
            .background(
                LinearGradient(gradient: Gradient(colors: [.buttongradient1, .buttongradient2]), startPoint: .top, endPoint: .bottom)
            )
            .cornerRadius(50)
            .shadow(color: .accentColor, radius: 5.0)
            .scaleEffect(isHovered ? 1.1 : 1.0)
            .contentShape(Circle())
            .onHover { hover in
                withAnimation(.easeInOut) {
                    isHovered = hover
                }
            }
        }
    }

    private func startScanAndShowResults() {
        let selectedCategory = selectedCat == "All" ? nil : selectedCat
        scanManager.startScan(category: selectedCategory)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            withAnimation(.easeInOut) {
                showScanResults = true
            }
        }
    }
}
