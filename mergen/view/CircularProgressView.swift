//
//  CircularProgressView.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import SwiftUI


struct CircularProgressView: View {
    var progress: Double

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.progresscolor.opacity(0.3), lineWidth: 5)
                .frame(width: 85, height: 85)

            Circle()
                .trim(from: 0.0, to: CGFloat(min(progress, 1.0)))
                .stroke(Color.accentColor, lineWidth: 10)
                .frame(width: 100, height: 100)
                .rotationEffect(Angle(degrees: 270.0))
                .onAppear {
                    withAnimation(.linear) {
                    }
                }
            Text("\(Int(progress * 100))%") // Add percentage text
                .font(.system(size: 30))
                .bold()
                .foregroundColor(.progresscolor)
        }
    }
}
