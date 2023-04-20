//
//  mergenApp.swift
//  mergen
//
//  Created by Samet Sazak
//

import SwiftUI
import AppKit


@main
struct MyApplication: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1115, maxWidth: .infinity, minHeight: 615, maxHeight: .infinity)
        }
        .windowStyle(HiddenTitleBarWindowStyle())
        .commands {
            SidebarCommands() // 1
            
        }
    }
    
    
}
