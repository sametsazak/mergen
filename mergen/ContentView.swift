//
//  ContentView.swift
//  mergen
//

import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var scanManager = ScanManager()
    @State private var selectedCategory: String? = nil
    @State private var selectedVulnerability: Vulnerability? = nil
    @State private var searchText = ""
    @State private var showLogViewer = false

    var body: some View {
        HStack(spacing: 0) {
            SidebarView(
                scanManager: scanManager,
                selectedCategory: $selectedCategory
            )
            .frame(width: 240)
            .background(Color(nsColor: .windowBackgroundColor))

            Divider()

            ResultsListView(
                scanManager: scanManager,
                selectedCategory: selectedCategory,
                selectedVulnerability: $selectedVulnerability,
                searchText: $searchText
            )
            .frame(minWidth: 320, idealWidth: 380)

            Divider()

            DetailPanelView(vulnerability: selectedVulnerability, scanManager: scanManager)
                .frame(minWidth: 280)
        }
        .frame(minWidth: 900, minHeight: 500)
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Button {
                    showLogViewer = true
                } label: {
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
