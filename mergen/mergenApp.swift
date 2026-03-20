//
//  mergenApp.swift
//  mergen
//
//  Created by Samet Sazak
//

import SwiftUI

@main
struct MergenApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1115, maxWidth: .infinity, minHeight: 615, maxHeight: .infinity)
        }
        .windowStyle(DefaultWindowStyle())
    }
}
