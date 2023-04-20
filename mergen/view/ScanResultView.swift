//
//  ScanResultView.swift
//  mergen
//
//  Created by Samet Sazak
//

import SwiftUI
import AppKit
import Quartz


struct ScanResultsView: View {
    
    @State private var isLHovered = false
    @State private var searchText: String = ""
    
    let scanResults: [Vulnerability]

    private var groupedScanResults: [String: [Vulnerability]] {
        Dictionary(grouping: scanResults, by: { $0.category })
            .filter { !$0.key.isEmpty }
    }
    
    @State private var selectedCategory: String = ""

    init(scanResults: [Vulnerability]) {
        self.scanResults = scanResults
    }
    private func saveHTMLStringToFile(_ htmlString: String) {
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "MergenResult.html"
        savePanel.allowedContentTypes = [UTType.html]

        if savePanel.runModal() == .OK, let url = savePanel.url {
            do {
                try htmlString.write(to: url, atomically: true, encoding: .utf8)
                print("HTML file saved to \(url)")
            } catch {
                print("Error saving HTML file: \(error)")
            }
        }
    }
    
    private func saveJSONToFile(_ jsonData: Data) {
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "MergenResult.json"
        savePanel.allowedContentTypes = [UTType.json]

        if savePanel.runModal() == .OK, let url = savePanel.url {
            do {
                try jsonData.write(to: url)
                print("JSON file saved to \(url)")
            } catch {
                print("Error saving JSON file: \(error)")
            }
        }
    }
    
    private var filteredResults: [Vulnerability] {
        if selectedCategory.isEmpty {
            if searchText.isEmpty {
                return scanResults
            } else {
                return scanResults.filter { vulnerability in
                    vulnerability.category.localizedCaseInsensitiveContains(searchText)
                        || vulnerability.name.localizedCaseInsensitiveContains(searchText)
                        || vulnerability.description.localizedCaseInsensitiveContains(searchText)
                        || (vulnerability.status != nil && vulnerability.status!.localizedCaseInsensitiveContains(searchText))
                }
            }
        } else {
            if searchText.isEmpty {
                return groupedScanResults[selectedCategory] ?? []
            } else {
                return (groupedScanResults[selectedCategory] ?? []).filter { vulnerability in
                    vulnerability.name.localizedCaseInsensitiveContains(searchText)
                        || vulnerability.description.localizedCaseInsensitiveContains(searchText)
                        || (vulnerability.status != nil && vulnerability.status!.localizedCaseInsensitiveContains(searchText))
                }
            }
        }
    }
    private func scanResultsToHTML() -> String {
        let generator = HTMLReportGenerator(scanResults: scanResults)
        return generator.generateHTMLReport()
    }
    
    var body: some View {
        ZStack {
//            Color.scanresultcolor.opacity(0.2)
            VStack {
                Spacer()
                // Add a picker to select the category filter
                Picker("Category", selection: $selectedCategory) {
                    Text("All").tag("").foregroundColor(.primary)
                    ForEach(groupedScanResults.keys.sorted().filter { $0 != "" }, id: \.self) { category in
                        Text(category).tag(category).foregroundColor(.primary)
                    }
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(.horizontal)
                .onChange(of: selectedCategory) { _ in
                    searchText = ""
                }

                List {
                    SearchField(text: $searchText)
                        .frame(width: 300)
                        .padding(.leading, 2)
                        .onChange(of: searchText) { _ in
                            
                        }
                    ForEach(filteredResults, id: \.id) { vulnerability in
                        NavigationLink(destination: VulnerabilityDetailView(vulnerability: vulnerability)){
                            VulnerabilityRow(vulnerability: vulnerability)
                        }
                        .listRowBackground(Color.scanresultcolor.opacity(0.2))
                    }
                }
                .listStyle(PlainListStyle())
                .opacity(0.8)
                Spacer()
            }
        }
        HStack {
            Button(action: {
                let htmlString = scanResultsToHTML()
                FileUtils.saveHTMLStringToFile(htmlString)
            }) {
                HStack {
                    Image(systemName: "square.and.arrow.up")
                        .font(.system(size: 20))
                        .foregroundColor(.black)
                    Text("Export Report")
                        .padding([.top, .leading, .bottom], 1.0)
                        .foregroundColor(.black)
                }
            }
            .buttonStyle(CustomButtonStyle())
            .padding(.leading, 0)

            Button(action: {
                let jsonGenerator = JSONReportGenerator(scanResults: scanResults)
                let jsonData = jsonGenerator.generateJSONReport()
                saveJSONToFile(jsonData)
            }) {
                HStack {
                    Image(systemName: "curlybraces")
                        .font(.system(size: 20))
                        .foregroundColor(.black)
                    Text("Export Json")
                        .padding([.top, .leading, .bottom], 1.0)
                        .foregroundColor(.black)
                }
            }
            .buttonStyle(CustomButtonStyle())
            .padding(.leading, 5)

            Spacer()
        }
        
    }
    
}


struct VulnerabilityRow: View {
    let vulnerability: Vulnerability
    
    func openURL(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }
    
    var body: some View {
        HStack {
            //First place before icons
            // Vulnerability row page details.
            getStatusIcon()
                .font(.title)
                .foregroundColor(getStatusColor())
                .frame(width: 30)
            Text(vulnerability.category)
                .font(.title3)
                .frame(minWidth: 120)
            VStack(alignment: .leading) {
                Text(vulnerability.name)
                    .font(.title3)
                Text(vulnerability.description)
                    .font(.subheadline)
                HStack {
                    Text(getStatusText())
                        .font(.subheadline)
                        .foregroundColor(getStatusColor())
                    getStatusIcon()
                        .foregroundColor(getStatusColor())
                    
//                    // Website forwarding button, VulnID will be used in the mergen.app
//                    Button("-> Detail") {
//
//                        let urlString = "https://abc.com/id/\(vulnerability.docID)"
//                        openURL(urlString)
//                    }
//                    .buttonStyle(.plain)
                }
            }
        }
        .padding()
    }
    
    private func getStatusText() -> String {
        switch vulnerability.checkstatus {
        case "Green":
            return vulnerability.status ?? "OK"
        case "Yellow":
            return vulnerability.status ?? "?"
        case "Red":
            return vulnerability.status ?? "Check this!"
        default:
            return vulnerability.status ?? "Unknown"
        }
    }
    
    private func getStatusIcon() -> Image {
        switch vulnerability.checkstatus {
        case "Green":
            return Image(systemName: "checkmark.seal")
        case "Yellow":
            return Image(systemName: "exclamationmark.triangle.fill")
        case "Red":
            return Image(systemName: "exclamationmark.triangle.fill")
        default:
            return Image(systemName: "questionmark")
        }
    }
    
    private func getStatusColor() -> Color {
        switch vulnerability.checkstatus {
        case "Green":
            return .green
        case "Yellow":
            return .yellow
        case "Red":
            return .red
        default:
            return .gray
        }
    }
}


struct SearchField: NSViewRepresentable {
    @Binding var text: String
    
    func makeNSView(context: Context) -> NSSearchField {
        let searchField = NSSearchField(frame: .zero)
        searchField.delegate = context.coordinator
        return searchField
    }
    
    func updateNSView(_ nsView: NSSearchField, context: Context) {
        nsView.stringValue = text
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    class Coordinator: NSObject, NSSearchFieldDelegate {
        let parent: SearchField
        
        init(parent: SearchField) {
            self.parent = parent
        }
        
        func controlTextDidChange(_ obj: Notification) {
            if let textField = obj.object as? NSTextField {
                parent.text = textField.stringValue
            }
        }
    }
}
