//
//  CustomButtonStyle.swift
//  mergen
//
//  Created by Samet Sazak on 5.04.2023.
//

import Foundation
import SwiftUI

struct CustomButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(width: 120, height: 50)
            .background(
                LinearGradient(gradient: Gradient(colors: [.grayish, .grayish]), startPoint: .top, endPoint: .bottom)
            )
            .cornerRadius(15)
    }
}

