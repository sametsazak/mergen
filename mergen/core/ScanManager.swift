//
//  ScanManager.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation
import Combine
import AppKit

class ScanManager: ObservableObject {
    @Published var scanResults: [Vulnerability] = []
    @Published var progress: Double = 0
    @Published var scanning: Bool = false
    private var totalModules: Int = 0
    
    func startScan(category: String?) {
        scanning = true
        DispatchQueue.global(qos: .userInitiated).async {
            let scanner = Scanner()
            if let category = category {
                scanner.loadModules(category: category)
            } else {
                scanner.loadModules()
            }
            self.totalModules = scanner.moduleCount
            var completedModules = 0
            
            scanner.modules.forEach { module in
                let timeout: DispatchTimeInterval = .seconds(15) // set timeout to 10 seconds
                
                let semaphore = DispatchSemaphore(value: 0)
                
                let taskQueue = DispatchQueue(label: "com.sametsazak.mergen", qos: .userInteractive)
                let task = taskQueue.async {
                    do {
                        print("Checking ---- : \(module.name)")
                        try module.check() // perform module check here
                    } catch let error {
                        print("Error in module check: \(error)") // log error message
                        print("ERROR ---- : \(module.name)")
                        module.checkstatus = "Yellow" // mark module as failed
                    }
                    
                    semaphore.signal()
                }
                
                let result = semaphore.wait(timeout: DispatchTime.now() + timeout)
                
                if result == .timedOut {
                    print("Module timed out") // log timeout message
                    module.checkstatus = "Yellow" // mark module as failed
                }
                
                DispatchQueue.main.async {
                    self.scanResults.append(module) // append module to scan results
                    completedModules += 1
                    self.progress = Double(completedModules) / Double(self.totalModules)
                    
                    if self.progress == 1 {
                        self.scanning = false
                    }
                }
            }
        }
    }




    func scanningComplete() {
        DispatchQueue.main.async {
            self.scanning = false
            // Process the results or update the UI as needed.
        }
    }
    func resetScan() {
        scanning = false
        progress = 0.0
        scanResults = []
    }
}


