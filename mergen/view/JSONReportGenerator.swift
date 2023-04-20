//
//  JSONReportGenerator.swift
//  mergen
//
//  Created by Samet Sazak on 7.04.2023.
//

import Foundation
import SwiftUI

struct ScanResult: Encodable {
    let name: String
    let description: String
    let category: String
    let remediation: String
    let severity: String
    let documentation: String?
    let status: String?
    let mitigation: String
    let docID: Int32
    
    init(vulnerability: Vulnerability) {
        self.name = vulnerability.name
        self.description = vulnerability.description
        self.category = vulnerability.category
        self.remediation = vulnerability.remediation
        self.severity = vulnerability.severity
        self.documentation = vulnerability.documentation
        self.status = vulnerability.status
        self.mitigation = vulnerability.mitigation
        self.docID = vulnerability.docID
    }
}

class JSONReportGenerator {
    let scanResults: [Vulnerability]

    init(scanResults: [Vulnerability]) {
        self.scanResults = scanResults
    }

    func generateJSONReport() -> Data {
        scanResultsToJSON()
    }

    private func scanResultsToJSON() -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted

        let scanResultArray = scanResults.map { ScanResult(vulnerability: $0) }

        do {
            let jsonData = try encoder.encode(scanResultArray)
            return jsonData
        } catch {
            print("Error encoding scan results to JSON: \(error)")
            return Data()
        }
    }
}
