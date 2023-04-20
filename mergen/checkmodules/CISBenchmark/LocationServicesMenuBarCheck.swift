//
//  LocationServicesMenuBarCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation


//This implementation checks whether the "Location.menu" item is present in the output of the defaults read com.apple.systemuiserver menuExtras command, which indicates that the Location Services icon is visible in the menu bar. If the "Location.menu" item is present, the status is set to "Location Services is visible in the menu bar", and the checkstatus is set to "Green". If the "Location.menu" item is not present, the status is set to "Location Services is not visible in the menu bar", and the checkstatus is set to "Red". If an error occurs during the check, the status is set to "Error checking menu bar status", and the checkstatus is set to "Yellow".


class LocationServicesMenuBarCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Location Services Is in the Menu Bar",
            description: "This check ensures that the Location Services icon is visible in the menu bar, providing users with awareness when Location Services is enabled.",
            category: "Privacy",
            remediation: "To enable Location Services in the menu bar, go to System Preferences > Security & Privacy > Privacy > Location Services and check the option.",
            severity: "Low",
            documentation: "Having the Location Services icon visible in the menu bar helps users to be aware of its status and manage location-based features more effectively.",
            mitigation: "Displaying the Location Services icon in the menu bar ensures that users are aware of when Location Services is enabled, reducing potential security risks.",
            docID: 51
        )
    }

    override func check() {
        let task = Process()
        task.launchPath = "/usr/bin/defaults"
        task.arguments = ["read", "com.apple.systemuiserver", "menuExtras"]

        let pipe = Pipe()
        task.standardOutput = pipe

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                if output.contains("Location.menu") {
                    status = "Location Services is visible in the menu bar"
                    checkstatus = "Green"
                } else {
                    status = "Location Services is not visible in the menu bar"
                    checkstatus = "Red"
                }
            } else {
                status = "Error parsing menu bar status"
                checkstatus = "Yellow"
            }
        } catch let e {
            print("Error checking \(name): \(e)")
            checkstatus = "Yellow"
            status = "Error checking menu bar status"
            self.error = e
        }
    }
}
