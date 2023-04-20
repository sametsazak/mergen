//
//  RouletteText.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import SwiftUI

struct RouletteText: View {
    let text: String
    let durationPerCharacter: TimeInterval
    
    @State private var revealedCharacters = 0

    var body: some View {
        Text(String(text.prefix(revealedCharacters)))
            .font(Font.custom("Helvetica", size: 25))
            .foregroundColor(.accentColor)
            //.shadow(color:.white, radius: 5.0)
            .onAppear {
                startRevealingCharacters()
            }
    }

    private func startRevealingCharacters() {
        Timer.scheduledTimer(withTimeInterval: durationPerCharacter, repeats: true) { timer in
            if revealedCharacters < text.count {
                revealedCharacters += 1
            } else {
                timer.invalidate()
            }
        }
    }
}
