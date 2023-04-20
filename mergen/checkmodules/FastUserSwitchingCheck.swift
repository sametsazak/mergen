//
//  FastUserSwitchingCheck.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class FastUserSwitchingCheck: Vulnerability {
    init() {
        super.init(
            name: "Check Fast User Switching Status",
            description: "This check ensures that Fast User Switching is disabled on your system, which helps prevent unauthorized access to your computer.",
            category: "Security",
            remediation: "To disable Fast User Switching, go to System Preferences > Users & Groups > Login Options, and uncheck the 'Show fast user switching menu as' option.",
            severity: "Medium",
            documentation: "For more information on disabling Fast User Switching, visit: https://support.apple.com/guide/mac-help/manage-users-groups-mtusr001/mac",
            mitigation: "By disabling Fast User Switching, you reduce the risk of unauthorized access to your computer when multiple user accounts are in use, enhancing its security.",
            docID: 35 // latest
        )
    }
    override func check() {
          let task = Process()
          task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
          task.arguments = ["read", "/Library/Preferences/.GlobalPreferences", "MultipleSessionEnabled"]

          let outputPipe = Pipe()
          task.standardOutput = outputPipe

          do {
              try task.run()
              task.waitUntilExit()

              let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
              let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

              if output.lowercased() == "0" {
                  status = "Fast User Switching is disabled"
                  checkstatus = "Green"
              } else {
                  status = "Fast User Switching is enabled."
                  checkstatus = "Red"
              }
          } catch let e {
              print("Error checking \(name): \(e)")
              checkstatus = "Yellow"
              status = "Error checking Fast User Switching status"
              self.error = e
          }
      }
  }
