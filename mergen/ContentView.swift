//
//  ContentView.swift
//  mergen
//
//  Created by Samet Sazak
//

import SwiftUI
import AppKit

struct ContentView: View {
    
    let catImages = [
        "All": "m1mini",
        "CIS Benchmark": "cisBenchmark",
        "Privacy": "privacymain",
        "Security": "security"
    ]
    
    @StateObject private var scanManager = ScanManager()
    @State private var showScanResults = false
    @State var show = false
    @State private var sidebarVisible = false
    @State private var imageOffset = CGSize.zero
    var cats = ["All", "CIS Benchmark", "Privacy", "Security"]
    @State private var selectedCat = "All"
    @State private var currentImage: String = "m1mini"
    
    private func startScanAndShowResults() {
        let selectedCategory = selectedCat == "All" ? nil : selectedCat
        scanManager.startScan(category: selectedCategory)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            withAnimation(.easeInOut(duration: 0.2)) {
                showScanResults = true
            }
        }
    }

//    private func startScanAndShowResults() {
//        scanManager.startScan()
//        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
//            withAnimation(.easeInOut(duration: 0.2)) {
//                showScanResults = true
//            }
//        }
//    }

    var body: some View {
        NavigationView {
            SidebarView(scanManager: scanManager, showScanResults: $showScanResults, selectedCat: $selectedCat)
                .frame(minWidth: 350)
            VStack {
                if showScanResults {
                    ScanResultsView(scanResults: scanManager.scanResults)
                        .transition(.move(edge: .bottom))
                } else {
                    Image(currentImage)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .padding(.top, 5.0)
                        .frame(width: 300, height: 300, alignment: .center)
                        .shadow(color: .black, radius: 5.0)
                        .rotation3DEffect(
                            Angle(degrees: 10),
                            axis: (x: 0.0, y: -1.0, z: 0.0)
                        )
                        .offset(imageOffset)
                        .onHover { isHovering in
                            withAnimation(.spring(response: 0.2, dampingFraction: 0.5, blendDuration: 0)) {
                                if isHovering {
                                    let deltaX = CGFloat.random(in: -10...10)
                                    let deltaY = CGFloat.random(in: -10...10)
                                    imageOffset = CGSize(width: deltaX, height: deltaY)
                                } else {
                                    imageOffset = CGSize.zero
                                }
                            }
                        }
                    HStack {
                        RouletteText(text: "The ultimate macOS audit and security check tool.", durationPerCharacter: 0.02)
                            .font(.largeTitle)
                    }
                    VStack {
                        Picker("Please choose a scan category", selection: $selectedCat) {
                            ForEach(cats, id: \.self) { category in
                                Text(category)
                                    .foregroundColor(.accentColor)
                            }
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        .padding(2)
                        .foregroundColor(.accentColor)
                        .onChange(of: selectedCat) { newValue in
                            withAnimation(.easeInOut(duration: 0.3)) {
                                currentImage = catImages[newValue] ?? "m1mini"
                            }
                        }
                    }

                    ScanButton(scanManager: scanManager, showScanResults: $showScanResults, selectedCat: $selectedCat)
                        .padding(.top, 30)
                    Spacer()
                    
                }
            }
            .padding()
            .background(
                LinearGradient(gradient: Gradient(colors: [.gradient, .gradient2, .gradient3]), startPoint: .top, endPoint: .bottom)
            )
//            .background(
//                LinearGradient(gradient: Gradient(colors: [.gradient, .gradient2, .gradient3]), startPoint: .top, endPoint: .bottom)
//            )
        }
        .background(
            LinearGradient(gradient: Gradient(colors: [.gradient, .gradient2, .gradient3]), startPoint: .top, endPoint: .bottom)
        )
        
    }
}
                   


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
