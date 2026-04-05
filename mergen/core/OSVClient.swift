//
//  OSVClient.swift
//  mergen
//
//  Queries the Google OSV database (osv.dev) for known vulnerabilities.
//  Free, no API key, no rate limits. Covers PyPI and npm.
//
//  NOTE: The querybatch endpoint only returns {id, modified} per vuln — no
//  details or references. We therefore do a two-step fetch:
//    1. querybatch  → which packages are vulnerable + their vuln IDs
//    2. GET /vulns/{id} per found ID (concurrent, capped at 10)  → full record
//

import Foundation

struct OSVClient {

    // MARK: - Shared decodable types

    private struct Vuln: Decodable {
        let id              : String
        let summary         : String?
        let details         : String?
        let published       : String?
        let aliases         : [String]?
        let severity        : [SeverityEntry]?
        let references      : [Reference]?
        let affected        : [Affected]?
        let databaseSpecific: DBSpecific?

        enum CodingKeys: String, CodingKey {
            case id, summary, details, published, aliases, severity, references, affected
            case databaseSpecific = "database_specific"
        }
    }
    private struct SeverityEntry: Decodable { let type: String; let score: String }
    private struct DBSpecific:    Decodable { let severity: String? }
    private struct Reference:     Decodable { let type: String; let url: String }

    private struct Affected: Decodable {
        let ranges: [AffectedRange]?
    }
    private struct AffectedRange: Decodable {
        let type  : String
        let events: [RangeEvent]?
    }
    private struct RangeEvent: Decodable {
        let introduced  : String?
        let fixed       : String?
        let lastAffected: String?
        enum CodingKeys: String, CodingKey {
            case introduced, fixed
            case lastAffected = "last_affected"
        }
    }

    // Batch response — only id+modified come back per vuln
    private struct BatchResponse: Decodable {
        let results: [QueryResult]
        struct QueryResult: Decodable {
            let vulns: [BatchVuln]?
        }
        struct BatchVuln: Decodable { let id: String }
    }

    // MARK: - Public API

    struct Package {
        let name     : String
        let version  : String
        let ecosystem: String   // "PyPI" or "npm"
    }

    struct Vulnerability {
        let id           : String
        let summary      : String
        let details      : String?
        let severity     : FindingSeverity
        let cveIDs       : [String]
        let references   : [String]
        let publishedDate: String?
        let fixedVersion : String?
    }

    private static let batchURL = URL(string: "https://api.osv.dev/v1/querybatch")!

    // MARK: - Public query

    /// Returns a map of packageName → vulnerabilities found.
    /// Step 1: querybatch (fast, gets IDs).
    /// Step 2: concurrent /vulns/{id} fetches (gets full details).
    static func queryBatch(packages: [Package]) async throws -> [String: [Vulnerability]] {
        guard !packages.isEmpty else { return [:] }

        var output: [String: [Vulnerability]] = [:]
        let chunks = stride(from: 0, to: packages.count, by: 500).map {
            Array(packages[$0..<min($0 + 500, packages.count)])
        }

        for chunk in chunks {
            // ── Step 1: batch check ────────────────────────────────────
            let bodyData = try JSONEncoder().encode(BatchRequest(queries: chunk.map {
                .init(package: .init(name: $0.name, ecosystem: $0.ecosystem), version: $0.version)
            }))

            var req = URLRequest(url: batchURL)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = bodyData
            req.timeoutInterval = 20

            let (data, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                throw URLError(.badServerResponse)
            }

            let parsed = try JSONDecoder().decode(BatchResponse.self, from: data)

            // Collect (pkgName, vulnID) pairs that need full fetches
            var toFetch: [(pkgName: String, id: String)] = []
            for (index, result) in parsed.results.enumerated() {
                guard index < chunk.count, let vulns = result.vulns, !vulns.isEmpty else { continue }
                let pkg = chunk[index]
                for v in vulns { toFetch.append((pkgName: pkg.name, id: v.id)) }
            }
            guard !toFetch.isEmpty else { continue }

            // ── Step 2: fetch full records concurrently (max 10 at once) ──
            let fullRecords = await fetchFullVulns(ids: toFetch.map { $0.id })

            for (pair, fullVuln) in zip(toFetch, fullRecords) {
                guard let v = fullVuln else { continue }
                let cves  = (v.aliases ?? []).filter { $0.hasPrefix("CVE-") }
                var refs  = (v.references ?? []).map { $0.url }
                // Always include a direct osv.dev link
                refs.insert("https://osv.dev/vulnerability/\(v.id)", at: 0)
                let fixed    = extractFixedVersion(from: v.affected)
                let dateStr  = v.published.flatMap { formatDate($0) }
                let vuln = Vulnerability(
                    id:           v.id,
                    summary:      v.summary ?? "Known vulnerability",
                    details:      cleanDetails(v.details),
                    severity:     parseSeverity(v),
                    cveIDs:       cves,
                    references:   refs,
                    publishedDate: dateStr,
                    fixedVersion: fixed
                )
                if output[pair.pkgName] == nil { output[pair.pkgName] = [vuln] }
                else { output[pair.pkgName]?.append(vuln) }
            }
        }
        return output
    }

    // MARK: - Reachability check

    static func checkReachability() async -> Bool {
        do {
            let body = """
            {"package":{"name":"test","ecosystem":"PyPI"},"version":"0.0.0"}
            """.data(using: .utf8)!
            var req = URLRequest(url: URL(string: "https://api.osv.dev/v1/query")!)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = body
            req.timeoutInterval = 6
            let (_, res) = try await URLSession.shared.data(for: req)
            return (res as? HTTPURLResponse)?.statusCode == 200
        } catch { return false }
    }

    // MARK: - Private: full vuln fetch

    /// Fetches full vuln records concurrently, at most 10 in flight at once.
    private static func fetchFullVulns(ids: [String]) async -> [Vuln?] {
        var results = Array(repeating: Optional<Vuln>.none, count: ids.count)
        // Process in batches of 10 to cap concurrency
        let batchSize = 10
        let batches = stride(from: 0, to: ids.count, by: batchSize).map {
            ($0, min($0 + batchSize, ids.count))
        }
        for (start, end) in batches {
            await withTaskGroup(of: (Int, Vuln?).self) { group in
                for i in start..<end {
                    let id = ids[i]
                    let idx = i
                    group.addTask {
                        guard let url = URL(string: "https://api.osv.dev/v1/vulns/\(id)") else {
                            return (idx, nil)
                        }
                        var req = URLRequest(url: url)
                        req.timeoutInterval = 12
                        do {
                            let (data, resp) = try await URLSession.shared.data(for: req)
                            guard (resp as? HTTPURLResponse)?.statusCode == 200 else { return (idx, nil) }
                            let v = try JSONDecoder().decode(Vuln.self, from: data)
                            return (idx, v)
                        } catch {
                            return (idx, nil)
                        }
                    }
                }
                for await (idx, vuln) in group {
                    results[idx] = vuln
                }
            }
        }
        return results
    }

    // MARK: - Severity parser

    private static func parseSeverity(_ v: Vuln) -> FindingSeverity {
        if let s = v.databaseSpecific?.severity {
            switch s.uppercased() {
            case "CRITICAL":          return .critical
            case "HIGH":              return .high
            case "MODERATE","MEDIUM": return .medium
            case "LOW":               return .low
            default: break
            }
        }
        for s in v.severity ?? [] {
            guard s.type.contains("CVSS") else { continue }
            let parts = s.score.components(separatedBy: "/")
            if let raw = parts.last, let val = Double(raw) {
                if val >= 9.0 { return .critical }
                if val >= 7.0 { return .high }
                if val >= 4.0 { return .medium }
                return .low
            }
        }
        return .medium
    }

    // MARK: - Helpers

    private static func extractFixedVersion(from affected: [Affected]?) -> String? {
        guard let affected else { return nil }
        for aff in affected {
            for range in aff.ranges ?? [] {
                guard range.type == "ECOSYSTEM" || range.type == "SEMVER" else { continue }
                for event in range.events ?? [] {
                    if let fixed = event.fixed, !fixed.isEmpty { return fixed }
                }
            }
        }
        return nil
    }

    private static func formatDate(_ iso: String) -> String? {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var date = fmt.date(from: iso)
        if date == nil {
            fmt.formatOptions = [.withInternetDateTime]
            date = fmt.date(from: iso)
        }
        guard let date else { return nil }
        let out = DateFormatter()
        out.dateStyle = .medium
        out.timeStyle = .none
        return out.string(from: date)
    }

    private static func cleanDetails(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        let lines = raw.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        var cleaned: [String] = []
        var lastBlank = false
        for line in lines {
            let blank = line.isEmpty
            if blank && lastBlank { continue }
            cleaned.append(line)
            lastBlank = blank
        }
        return cleaned.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Batch request type (private)

private struct BatchRequest: Encodable {
    let queries: [Query]
    struct Query: Encodable {
        let package: Pkg
        let version: String
        struct Pkg: Encodable { let name: String; let ecosystem: String }
    }
}
