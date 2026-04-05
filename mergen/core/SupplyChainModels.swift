//
//  SupplyChainModels.swift
//  mergen
//
//  Data model for the Supply Chain Threat Surface scanner.
//

import SwiftUI

// MARK: - Threat Finding

struct ThreatFinding: Identifiable, Hashable {
    let id              = UUID()
    let category        : ThreatCategory
    let severity        : FindingSeverity
    let title           : String
    let detail          : String
    let source          : FindingSource
    let location        : String?
    let cveIDs          : [String]
    let remediation     : String
    let fixCommand      : String?  // nil = not auto-fixable
    let fixRequiresAdmin: Bool     // true = needs admin privileges
    let references      : [String] // advisory / report URLs (from OSV)
    let publishedDate   : String?  // e.g. "Jan 15, 2024"
    let fixedVersion    : String?  // version that resolves the issue

    var isFixable: Bool { fixCommand != nil }

    init(category: ThreatCategory, severity: FindingSeverity, title: String, detail: String,
         source: FindingSource, location: String?, cveIDs: [String], remediation: String,
         fixCommand: String? = nil, fixRequiresAdmin: Bool = false,
         references: [String] = [], publishedDate: String? = nil, fixedVersion: String? = nil) {
        self.category         = category
        self.severity         = severity
        self.title            = title
        self.detail           = detail
        self.source           = source
        self.location         = location
        self.cveIDs           = cveIDs
        self.remediation      = remediation
        self.fixCommand       = fixCommand
        self.fixRequiresAdmin = fixRequiresAdmin
        self.references       = references
        self.publishedDate    = publishedDate
        self.fixedVersion     = fixedVersion
    }

    func hash(into hasher: inout Hasher) { hasher.combine(id) }
    static func == (lhs: ThreatFinding, rhs: ThreatFinding) -> Bool { lhs.id == rhs.id }
}

// MARK: - Category

enum ThreatCategory: String, CaseIterable {
    case persistence = "Persistence"
    case npm         = "npm"
    case python      = "Python"
    case homebrew    = "Homebrew"
    case llm         = "LLM Models"

    var icon: String {
        switch self {
        case .persistence: return "bolt.trianglebadge.exclamationmark.fill"
        case .npm:         return "shippingbox.fill"
        case .python:      return "chevron.left.forwardslash.chevron.right"
        case .homebrew:    return "cup.and.saucer.fill"
        case .llm:         return "cpu"
        }
    }

    var color: Color {
        switch self {
        case .persistence: return Color(red: 0.85, green: 0.25, blue: 0.25)
        case .npm:         return Color(red: 0.80, green: 0.52, blue: 0.10)
        case .python:      return Color(red: 0.20, green: 0.52, blue: 0.85)
        case .homebrew:    return Color(red: 0.85, green: 0.45, blue: 0.15)
        case .llm:         return Color(red: 0.55, green: 0.25, blue: 0.85)
        }
    }
}

// MARK: - Severity

enum FindingSeverity: String, CaseIterable, Comparable {
    case critical = "Critical"
    case high     = "High"
    case medium   = "Medium"
    case low      = "Low"
    case info     = "Info"

    private var order: Int {
        switch self { case .critical: return 0; case .high: return 1; case .medium: return 2; case .low: return 3; case .info: return 4 }
    }
    static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool { lhs.order < rhs.order }

    var color: Color {
        switch self {
        case .critical: return Color(red: 0.90, green: 0.15, blue: 0.15)
        case .high:     return Color(red: 0.85, green: 0.25, blue: 0.25)
        case .medium:   return Color(red: 0.80, green: 0.52, blue: 0.10)
        case .low:      return Color(red: 0.60, green: 0.55, blue: 0.10)
        case .info:     return Color.secondary
        }
    }
}

// MARK: - Source

enum FindingSource: String {
    case localAnalysis  = "Local"
    case osv            = "OSV"
    case ossfMalicious  = "OSSF"   // Confirmed malicious via OSSF malicious-packages feed
    case pipAudit       = "pip-audit"
}

// MARK: - Tool availability

struct SupplyChainSourceStatus {
    var osvReachable      : Bool? = nil   // nil = not yet checked
    var npmPath           : String? = nil
    var pipPath           : String? = nil
    var pipAuditPath      : String? = nil
    var brewPath          : String? = nil

    var npmInstalled:     Bool { npmPath  != nil }
    var pipInstalled:     Bool { pipPath  != nil }
    var pipAuditInstalled:Bool { pipAuditPath != nil }
    var brewInstalled:    Bool { brewPath != nil }
}
