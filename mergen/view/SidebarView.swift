//
//  SidebarView.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import SwiftUI

struct SidebarView: View {
    @ObservedObject var scanManager: ScanManager
    @Binding var showScanResults: Bool
    @State private var isLoading = false
    @State private var isExporting = false
    @State private var isScanCompleted = false
    @State private var isHovered = false
    @Binding var selectedCat: String
    
    func descriptionAndImageForCategory(_ category: String) -> (description: String, imageName: String) {
        switch category {
        case "CIS Benchmark":
            let description = "Set of security configuration best practices."
            let imageName = "lock.laptopcomputer"
            return (description: description, imageName: imageName)
        case "Privacy":
            let description = "Privacy checks focus on protecting your personal information."
            let imageName = "eye.trianglebadge.exclamationmark"
            return (description: description, imageName: imageName)
        case "Security":
            let description = "Security checks help ensure the safety of your system."
            let imageName = "lock.rectangle.on.rectangle"
            return (description: description, imageName: imageName)
        default:
            let description = "All categories will be scanned"
            let imageName = "shield.lefthalf.filled.slash"
            return (description: description, imageName: imageName)
        }
    }


    func resetToInitialState() {
        withAnimation(.easeInOut(duration: 0.2)) {
            showScanResults = false
        }
        scanManager.resetScan()
        isScanCompleted = false
    }
    
    func showLastScanResults() {
        withAnimation(.easeInOut(duration: 0.2)) {
            showScanResults = true
        }
    }

    var body: some View {
        
        let categoryInfo = descriptionAndImageForCategory(selectedCat)
        VStack(alignment: .center, spacing: 0) {
            Text(selectedCat)
                .foregroundColor(.accentColor)
                .font(Font.custom("Helvetica", size: 25))
                .bold()
                .padding(.top, 120)
                .transition(AnyTransition.opacity.combined(with: .scale(scale: 0.9)))
                .animation(.easeInOut(duration: 0.5), value: selectedCat)
            Image(systemName: categoryInfo.imageName)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .foregroundColor(.accentColor)
                .frame(width: 75, height: 70)
                .transition(AnyTransition.opacity.combined(with: .scale(scale: 0.9)))
                .animation(.easeInOut, value: selectedCat)
                .padding(.top, 15)
            Text(categoryInfo.description)
                .foregroundColor(.accentColor)
                .font(Font.custom("Helvetica", size: 15))
                .padding([.top, .leading, .trailing], 5)
                .transition(AnyTransition.opacity.combined(with: .scale(scale: 0.9)))
                .animation(.easeInOut(duration: 0.5), value: selectedCat)
            VStack(alignment: .center, spacing: 0) {
                Spacer()
                if scanManager.scanning {
                    VStack {
                        CircularProgressView(progress: scanManager.progress)
                            .opacity(scanManager.scanning ? 1.0 : 0.0)
                        Text("Scan process can take time, please wait...")
                            .font(Font.custom("Helvetica", size: 15))
                            .foregroundColor(.accentColor)
                            .padding(.bottom, 10)
                    }
                }
                
                if !scanManager.scanning && !scanManager.scanResults.isEmpty {
                    HStack(spacing: 20) {
                        Button(action: {
                            resetToInitialState()
                        }) {
                            Image(systemName: "arrow.left.circle.fill")
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
                        .shadow(color: .accentColor, radius: 5)
                        .scaleEffect(isHovered ? 1.1 : 1.0) // Apply scale effect based on hover state
                        .contentShape(Circle()) // Increase the tappable area to cover the entire circle
                        .onHover { hover in // Update hover state
                            withAnimation(.easeInOut) {
                                isHovered = hover
                            }
                        }
                        
                    }
                    Divider()
                        .padding(15)
                    Text("Scan Result")
                        .foregroundColor(.accentColor)
                            .padding(15)
                            .font(.title2)
                    ScanResultIndicator(scanResults: scanManager.scanResults)
                        .transition(.move(edge: .trailing))
                }
                Spacer()
            }
            .padding(.top, 25)
            .frame(maxWidth: .infinity)
            .background(Color.clear)
        }
        .background(
            LinearGradient(gradient: Gradient(colors: [.gradient, .gradient2, .gradient3]), startPoint: .top, endPoint: .bottom)
        )

        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    
}
