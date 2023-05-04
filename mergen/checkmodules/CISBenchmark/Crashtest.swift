//
//  Crashtest.swift
//  mergen
//
//  Created by Samet Sazak on 4.05.2023.
//

import Foundation

class Crashtest: Vulnerability {
    init() {
        super.init(
            name: "This is a Crashtest",
            description: "Crashtest",
            category: "CIS Benchmark",
            remediation: "Crashtest",
            severity: "High",
            documentation: "XXXX",
            mitigation: "XXXXXXXX",
            checkstatus: "",
            docID: 19
        )
    }
    
    func crash() {
        NSException(name: NSExceptionName(rawValue: "IntentionalCrash"), reason: "This is an intentional crash for testing purposes.", userInfo: nil).raise()
    }
    
    override func check() {
        crash()
    }
    
}
