//
//  SupplyChainScanner.swift
//  mergen
//
//  Orchestrates all supply-chain threat checks:
//    Layer 1 — local analysis (no network, catches zero-days)
//    Layer 2 — OSV batch query (known CVEs, PyPI + npm)
//    Layer 3 — pip-audit wrapper (if installed)
//

import Foundation
import AppKit

@MainActor
class SupplyChainScanner: ObservableObject {

    @Published var findings     : [ThreatFinding] = []
    @Published var isScanning   : Bool = false
    @Published var progress     : Double = 0
    @Published var hasResults   : Bool = false
    @Published var sourceStatus : SupplyChainSourceStatus = .init()

    // Fix orchestration
    @Published var fixingIDs   : Set<UUID>    = []
    @Published var fixResults  : [UUID: Bool] = [:]
    @Published var fixCancelled: Set<UUID>    = []

    // MARK: - Public

    func startScan() {
        guard !isScanning else { return }
        findings   = []
        progress   = 0
        hasResults = false
        isScanning = true
        Task { await runScan() }
    }

    func reset() {
        isScanning   = false
        findings     = []
        progress     = 0
        hasResults   = false
        sourceStatus = .init()
        fixingIDs    = []
        fixResults   = [:]
        fixCancelled = []
    }

    // MARK: - Fix Orchestration

    func applyFix(for finding: ThreatFinding) {
        guard finding.isFixable, let cmd = finding.fixCommand else { return }
        guard !fixingIDs.contains(finding.id) else { return }
        let id = finding.id
        let requiresAdmin = finding.fixRequiresAdmin
        fixingIDs.insert(id)
        Task.detached { [weak self] in
            let result: FixResult = requiresAdmin
                ? FixManager.runAdminCommand(cmd)
                : FixManager.runUserCommand(cmd)
            await MainActor.run {
                guard let self else { return }
                self.fixingIDs.remove(id)
                switch result {
                case .success:     self.fixResults[id]   = true
                case .scriptError: self.fixResults[id]   = false
                case .cancelled:   self.fixCancelled.insert(id)
                }
            }
        }
    }

    /// Applies all fixable findings: user-level fixes run individually,
    /// admin fixes are batched into a single password prompt.
    func fixAll(_ findings: [ThreatFinding]) {
        let fixable    = findings.filter { $0.isFixable && !fixingIDs.contains($0.id) && fixResults[$0.id] == nil }
        let userFixes  = fixable.filter { !$0.fixRequiresAdmin }
        let adminFixes = fixable.filter {  $0.fixRequiresAdmin }
        guard !fixable.isEmpty else { return }

        fixingIDs.formUnion(fixable.map { $0.id })

        Task.detached { [weak self] in
            // ── User-level fixes ─────────────────────────────────────────
            for f in userFixes {
                guard let cmd = f.fixCommand else { continue }
                let result = FixManager.runUserCommand(cmd)
                await MainActor.run {
                    guard let self else { return }
                    self.fixingIDs.remove(f.id)
                    switch result {
                    case .success:     self.fixResults[f.id]   = true
                    case .scriptError: self.fixResults[f.id]   = false
                    case .cancelled:   self.fixCancelled.insert(f.id)
                    }
                }
            }

            // ── Admin fixes — ONE password prompt for all ────────────────
            if !adminFixes.isEmpty {
                let combined = adminFixes.compactMap { $0.fixCommand }.joined(separator: " ; ")
                let result   = FixManager.runAdminCommand(combined)
                await MainActor.run {
                    guard let self else { return }
                    for f in adminFixes {
                        self.fixingIDs.remove(f.id)
                        switch result {
                        case .success:     self.fixResults[f.id]   = true
                        case .scriptError: self.fixResults[f.id]   = false
                        case .cancelled:   self.fixCancelled.insert(f.id)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Main scan pipeline

    private func runScan() async {
        // ── Detect tools ────────────────────────────────────────────────
        let status = await Task.detached { detectTools() }.value
        sourceStatus = status
        advance(to: 0.05)

        // ── Fetch package lists early — needed by both typosquatting and OSV ──
        async let pipPkgsF = Task.detached { status.pipInstalled ? getPipPackages(pipPath: status.pipPath!)  : [] }.value
        async let npmPkgsF = Task.detached { status.npmInstalled ? getNpmPackages(npmPath: status.npmPath!)  : [] }.value
        let (pipPkgs, npmPkgs) = await (pipPkgsF, npmPkgsF)
        advance(to: 0.12)

        // ── Layer 1: Local analysis (all in parallel) ────────────────────
        async let launchF  = Task.detached { scanLaunchAgents()  }.value
        async let cronF    = Task.detached { scanCronJobs()      }.value
        async let llmF     = Task.detached { scanLLMModels()     }.value
        async let brewF    = Task.detached { status.brewInstalled ? scanHomebrewTaps(brewPath: status.brewPath!) : [] }.value
        async let npmLF    = Task.detached { status.npmInstalled  ? scanNpmPostinstall(npmPath: status.npmPath!)  : [] }.value
        async let typoF    = Task.detached { scanTyposquatting(pip: pipPkgs, npm: npmPkgs) }.value
        async let pthF     = Task.detached { status.pipInstalled  ? scanPythonPthFiles(pipPath: status.pipPath!)  : [] }.value

        let local = await launchF + cronF + llmF + brewF + npmLF + typoF + pthF
        append(local)
        advance(to: 0.40)

        // ── Layer 2: OSV — pip ────────────────────────────────────────────
        if !pipPkgs.isEmpty {
            do {
                let osvPkgs = pipPkgs.map { OSVClient.Package(name: $0.name, version: $0.version, ecosystem: "PyPI") }
                let vulnMap = try await OSVClient.queryBatch(packages: osvPkgs)
                sourceStatus.osvReachable = true
                let osvFindings = buildOSVFindings(from: vulnMap, ecosystem: "PyPI", totalScanned: pipPkgs.count)
                append(osvFindings)
            } catch {
                sourceStatus.osvReachable = false
            }
        }
        advance(to: 0.65)

        // ── Layer 2: OSV — npm ────────────────────────────────────────────
        if !npmPkgs.isEmpty {
            do {
                let osvPkgs = npmPkgs.map { OSVClient.Package(name: $0.name, version: $0.version, ecosystem: "npm") }
                let vulnMap = try await OSVClient.queryBatch(packages: osvPkgs)
                if sourceStatus.osvReachable == nil { sourceStatus.osvReachable = true }
                let osvFindings = buildOSVFindings(from: vulnMap, ecosystem: "npm", totalScanned: npmPkgs.count)
                append(osvFindings)
            } catch {
                if sourceStatus.osvReachable == nil { sourceStatus.osvReachable = false }
            }
        }
        advance(to: 0.85)

        // ── Layer 3: pip-audit ────────────────────────────────────────────
        if status.pipAuditInstalled {
            let auditFindings = await Task.detached { runPipAudit(path: status.pipAuditPath!) }.value
            let existingLocations = Set(findings.filter { $0.source == .osv && $0.category == .python }.compactMap { $0.location })
            let deduplicated = auditFindings.filter { !existingLocations.contains($0.location ?? "") }
            append(deduplicated)
        }

        advance(to: 1.0)
        isScanning = false
        hasResults = true
    }

    // MARK: - Helpers

    private func advance(to value: Double) { progress = value }
    private func append(_ items: [ThreatFinding]) { findings.append(contentsOf: items) }
}

// MARK: - Tool Detection (nonisolated)

private func detectTools() -> SupplyChainSourceStatus {
    var s = SupplyChainSourceStatus()
    s.npmPath      = which("npm")
    s.pipPath      = which("pip3") ?? which("pip")
    s.pipAuditPath = which("pip-audit")
    s.brewPath     = which("brew")
    return s
}

private func which(_ tool: String) -> String? {
    let searchPaths = [
        "/opt/homebrew/bin/\(tool)",
        "/usr/local/bin/\(tool)",
        "/usr/bin/\(tool)",
        "/bin/\(tool)"
    ]
    // Try known paths first
    for path in searchPaths {
        if FileManager.default.isExecutableFile(atPath: path) { return path }
    }
    // Fall back to /usr/bin/which
    let out = shell("/usr/bin/which", [tool])
    let trimmed = out.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

// MARK: - Layer 1: Launch Agents / Daemons

private func scanLaunchAgents() -> [ThreatFinding] {
    let home = NSHomeDirectory()
    let dirs = [
        home + "/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons"
    ]
    let writablePrefixes = ["/tmp", "/private/tmp", home + "/Downloads", home + "/Desktop",
                             home + "/Library/Application Support", home + "/Library/Caches"]
    let appleIDs = ["com.apple.", "com.openssh.", "com.microsoft.", "com.google."]

    var findings: [ThreatFinding] = []

    for dir in dirs {
        guard let plists = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
        for plist in plists where plist.hasSuffix(".plist") {
            let path = dir + "/" + plist
            guard let data = FileManager.default.contents(atPath: path),
                  let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            else { continue }

            let label = dict["Label"] as? String ?? plist

            // Skip known Apple/system entries
            if appleIDs.contains(where: { label.hasPrefix($0) }) { continue }

            // Get the binary being launched
            var binary = ""
            if let prog = dict["Program"] as? String {
                binary = prog
            } else if let args = dict["ProgramArguments"] as? [String], let first = args.first {
                binary = first
            }

            // Flag 1: points to a writable / suspicious path
            let isWritablePath = writablePrefixes.contains { binary.hasPrefix($0) }

            // Flag 2: binary doesn't exist
            let binaryMissing = !binary.isEmpty && !FileManager.default.fileExists(atPath: binary)

            // Flag 3: recently modified (within 14 days) — new persistence
            var recentlyAdded = false
            if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let modified = attrs[.modificationDate] as? Date {
                recentlyAdded = Date().timeIntervalSince(modified) < 14 * 24 * 3600
            }

            let isSystemPath = path.hasPrefix("/Library/")

            if isWritablePath {
                findings.append(ThreatFinding(
                    category:        .persistence,
                    severity:        .high,
                    title:           "Launch Agent points to writable path",
                    detail:          "\(label) → \(binary)",
                    source:          .localAnalysis,
                    location:        path,
                    cveIDs:          [],
                    remediation:     "Inspect \(path). If unrecognised, remove with: launchctl unload '\(path)' && rm '\(path)'",
                    fixCommand:      "launchctl unload '\(path)' 2>/dev/null; rm '\(path)'",
                    fixRequiresAdmin: isSystemPath
                ))
            } else if binaryMissing && !binary.isEmpty {
                findings.append(ThreatFinding(
                    category:        .persistence,
                    severity:        .medium,
                    title:           "Launch Agent references missing binary",
                    detail:          "\(label) → \(binary) (not found)",
                    source:          .localAnalysis,
                    location:        path,
                    cveIDs:          [],
                    remediation:     "The binary this Launch Agent references no longer exists. Remove with: rm '\(path)'",
                    fixCommand:      "rm '\(path)'",
                    fixRequiresAdmin: isSystemPath
                ))
            } else if recentlyAdded {
                findings.append(ThreatFinding(
                    category:    .persistence,
                    severity:    .low,
                    title:       "Recently added Launch Agent — review recommended",
                    detail:      "\(label) was added or modified in the last 14 days",
                    source:      .localAnalysis,
                    location:    path,
                    cveIDs:      [],
                    remediation: "Verify that \(label) was added by a trusted application. If unexpected, remove it."
                ))
            }
        }
    }
    return findings
}

// MARK: - Layer 1: Cron Jobs

private func scanCronJobs() -> [ThreatFinding] {
    let output = shell("/usr/bin/crontab", ["-l"])
    let lines = output.components(separatedBy: "\n")
        .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    guard !lines.isEmpty else { return [] }

    return [ThreatFinding(
        category:    .persistence,
        severity:    .medium,
        title:       "User cron jobs detected (\(lines.count) entr\(lines.count == 1 ? "y" : "ies"))",
        detail:      lines.prefix(3).joined(separator: " | ") + (lines.count > 3 ? " …" : ""),
        source:      .localAnalysis,
        location:    "crontab",
        cveIDs:      [],
        remediation: "Cron jobs are uncommon on macOS. Run 'crontab -l' to review. Remove with 'crontab -r' if not needed."
    )]
}

// MARK: - Layer 1: LLM Model Files

private func scanLLMModels() -> [ThreatFinding] {
    let home = NSHomeDirectory()
    let knownDirs = [
        home + "/.ollama",
        home + "/.lmstudio",
        home + "/LMStudio-Models",
        home + "/.cache/huggingface",
        home + "/.cache/lm-studio",
        home + "/Library/Application Support/nomic.ai",
    ]
    let dangerousExts = ["pkl", "pt", "pth"]   // pickle — can exec arbitrary code
    let modelExts     = ["gguf", "safetensors", "bin", "ggml"]

    var findings: [ThreatFinding] = []
    let fm = FileManager.default

    func isInsideKnownDir(_ path: String) -> Bool {
        knownDirs.contains { path.hasPrefix($0) }
    }

    func hasQuarantineFlag(_ path: String) -> Bool {
        let out = shell("/usr/bin/xattr", ["-p", "com.apple.quarantine", path])
        return !out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    // Scan home dir for pickle/torch files (always dangerous)
    let searchDirs = [home + "/Downloads", home + "/Documents", home + "/Desktop",
                      home + "/.cache", home + "/.local"]
    for dir in searchDirs {
        guard let enumerator = fm.enumerator(atPath: dir) else { continue }
        for case let file as String in enumerator {
            let ext = (file as NSString).pathExtension.lowercased()
            let fullPath = dir + "/" + file
            guard dangerousExts.contains(ext) || modelExts.contains(ext) else { continue }

            if dangerousExts.contains(ext) {
                findings.append(ThreatFinding(
                    category:    .llm,
                    severity:    .high,
                    title:       "Pickle/Torch model file — arbitrary code risk",
                    detail:      fullPath,
                    source:      .localAnalysis,
                    location:    fullPath,
                    cveIDs:      [],
                    remediation: "Pickle format allows code execution on load. Verify the source of this file. Prefer .safetensors format. Remove if origin is unknown."
                ))
            } else if modelExts.contains(ext) && !isInsideKnownDir(fullPath) && !hasQuarantineFlag(fullPath) {
                findings.append(ThreatFinding(
                    category:    .llm,
                    severity:    .medium,
                    title:       "LLM model outside known model directory — no quarantine flag",
                    detail:      fullPath,
                    source:      .localAnalysis,
                    location:    fullPath,
                    cveIDs:      [],
                    remediation: "This model file was likely not downloaded via a standard app (no macOS quarantine flag). Verify its origin. Remove if unknown."
                ))
            }
        }
    }
    return findings
}

// MARK: - Layer 1: Homebrew Taps

private func scanHomebrewTaps(brewPath: String) -> [ThreatFinding] {
    let output = shell(brewPath, ["tap"])
    let taps = output.components(separatedBy: "\n")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }

    let officialTaps = ["homebrew/core", "homebrew/cask", "homebrew/cask-fonts",
                        "homebrew/cask-versions", "homebrew/services"]
    let unofficial = taps.filter { tap in !officialTaps.contains(tap) }
    guard !unofficial.isEmpty else { return [] }

    return unofficial.map { tap in
        ThreatFinding(
            category:    .homebrew,
            severity:    .medium,
            title:       "Unofficial Homebrew tap: \(tap)",
            detail:      "Tap formulae are unvetted Ruby scripts that run arbitrary code during install. A compromised or malicious tap can install anything.",
            source:      .localAnalysis,
            location:    tap,
            cveIDs:      [],
            remediation: "If you no longer use this tap, remove it with: brew untap \(tap)",
            fixCommand:  "brew untap \(tap)"
        )
    }
}

// MARK: - Layer 1: npm postinstall script analysis

private func scanNpmPostinstall(npmPath: String) -> [ThreatFinding] {
    // Find global node_modules
    let rootOutput = shell(npmPath, ["root", "-g"])
    let root = rootOutput.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !root.isEmpty, FileManager.default.fileExists(atPath: root) else { return [] }

    let suspiciousPatterns = ["curl", "wget", "base64", "eval", "exec(",
                              "/bin/sh", "/bin/bash", "child_process", "btoa", "atob"]
    var findings: [ThreatFinding] = []

    guard let packages = try? FileManager.default.contentsOfDirectory(atPath: root) else { return [] }
    for pkg in packages {
        let pkgJsonPath = root + "/" + pkg + "/package.json"
        guard let data = FileManager.default.contents(atPath: pkgJsonPath),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let scripts = json["scripts"] as? [String: Any] else { continue }

        let hooks = ["preinstall", "install", "postinstall"]
        for hook in hooks {
            guard let script = scripts[hook] as? String else { continue }
            let matched = suspiciousPatterns.filter { script.contains($0) }
            guard !matched.isEmpty else { continue }

            let version = (json["version"] as? String) ?? "unknown"
            findings.append(ThreatFinding(
                category:    .npm,
                severity:    .high,
                title:       "Suspicious \(hook) script: \(pkg)@\(version)",
                detail:      "Script contains: \(matched.joined(separator: ", ")) — \"\(script.prefix(120))\"",
                source:      .localAnalysis,
                location:    pkg,
                cveIDs:      [],
                remediation: "Inspect \(pkgJsonPath). If the script is unexpected, uninstall with: npm uninstall -g \(pkg)",
                fixCommand:  "npm uninstall -g \(pkg)"
            ))
        }
    }
    return findings
}

// MARK: - Layer 1: Typosquatting Detection

/// Well-known PyPI packages. Installed packages within edit-distance 1 of these
/// (but not exactly matching) are flagged as possible typosquats.
private let popularPyPIPackages: Set<String> = [
    "requests", "numpy", "pandas", "setuptools", "pip", "urllib3", "certifi",
    "charset-normalizer", "idna", "packaging", "six", "python-dateutil",
    "botocore", "boto3", "cryptography", "typing-extensions", "attrs",
    "click", "flask", "django", "pillow", "scipy", "matplotlib", "colorama",
    "tqdm", "pyyaml", "toml", "virtualenv", "black", "pytest", "mypy",
    "paramiko", "torch", "tensorflow", "psutil", "sqlalchemy", "celery",
    "redis", "pymongo", "aiohttp", "twisted", "scrapy", "fastapi", "uvicorn",
    "httpx", "rich", "typer", "pydantic", "arrow", "pendulum", "httplib2",
    "pyopenssl", "cffi", "cachetools", "google-auth", "protobuf", "grpcio",
    "werkzeug", "jinja2", "markupsafe", "itsdangerous", "wtforms"
]

/// Well-known globally-installed npm packages.
private let popularNPMPackages: Set<String> = [
    "typescript", "eslint", "prettier", "nodemon", "pm2", "mocha", "jest",
    "webpack", "express", "lodash", "axios", "moment", "chalk", "commander",
    "dotenv", "http-server", "serve", "gatsby-cli", "create-react-app",
    "create-next-app", "vue", "nuxt", "yarn", "pnpm", "vercel", "netlify-cli",
    "aws-cdk", "svelte", "tailwindcss", "vite", "rollup", "esbuild", "nx",
    "electron", "parcel", "browserify", "grunt", "gulp", "bower", "lerna",
    "tsc", "ts-node", "babel", "babel-cli", "rimraf", "cross-env", "concurrently"
]

private func scanTyposquatting(pip: [SimplePackage], npm: [SimplePackage]) -> [ThreatFinding] {
    var findings: [ThreatFinding] = []

    for pkg in pip {
        // Normalise: lowercase, underscores → hyphens (PyPI canonical)
        let name = pkg.name.lowercased().replacingOccurrences(of: "_", with: "-")
        guard name.count > 4 else { continue }
        for popular in popularPyPIPackages {
            if name == popular { break }              // exact match — legitimate
            if levenshteinDistance(name, popular) == 1 {
                findings.append(ThreatFinding(
                    category:    .python,
                    severity:    .high,
                    title:       "Possible typosquatting: \(pkg.name)",
                    detail:      "'\(pkg.name)' is one character away from the popular package '\(popular)'. Attackers publish packages with nearly identical names to trick developers into installing malware instead of the real package.",
                    source:      .localAnalysis,
                    location:    pkg.name,
                    cveIDs:      [],
                    remediation: "If this was an accidental install instead of '\(popular)', uninstall it now and install the correct package.",
                    fixCommand:  "pip3 uninstall -y \(pkg.name)"
                ))
                break
            }
        }
    }

    for pkg in npm {
        let name = pkg.name.lowercased()
        // Skip scoped packages (@org/name) and very short names
        guard name.count > 4, !name.hasPrefix("@") else { continue }
        for popular in popularNPMPackages {
            if name == popular { break }
            if levenshteinDistance(name, popular) == 1 {
                findings.append(ThreatFinding(
                    category:    .npm,
                    severity:    .high,
                    title:       "Possible typosquatting: \(pkg.name)",
                    detail:      "'\(pkg.name)' is one character away from the popular npm package '\(popular)'. This is a classic supply chain attack vector — the npm registry has had hundreds of confirmed typosquatting incidents.",
                    source:      .localAnalysis,
                    location:    pkg.name,
                    cveIDs:      [],
                    remediation: "If this was an accidental install instead of '\(popular)', uninstall it now.",
                    fixCommand:  "npm uninstall -g \(pkg.name)"
                ))
                break
            }
        }
    }

    return findings
}

/// Standard Levenshtein edit distance.
private func levenshteinDistance(_ a: String, _ b: String) -> Int {
    let a = Array(a), b = Array(b)
    let m = a.count, n = b.count
    guard m > 0 else { return n }
    guard n > 0 else { return m }
    // Early exit: length difference alone exceeds threshold
    if abs(m - n) > 2 { return abs(m - n) }
    var dp = Array(repeating: Array(repeating: 0, count: n + 1), count: m + 1)
    for i in 0...m { dp[i][0] = i }
    for j in 0...n { dp[0][j] = j }
    for i in 1...m {
        for j in 1...n {
            dp[i][j] = a[i-1] == b[j-1]
                ? dp[i-1][j-1]
                : 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
        }
    }
    return dp[m][n]
}

// MARK: - Layer 1: Python .pth File Analysis

/// Python .pth files in site-packages that contain "import " statements execute
/// arbitrary code on every Python startup — a common malicious persistence trick.
private func scanPythonPthFiles(pipPath: String) -> [ThreatFinding] {
    // Ask pip where site-packages lives
    let showOut = shell(pipPath, ["show", "pip"])
    var siteDir = ""
    for line in showOut.components(separatedBy: "\n") {
        if line.hasPrefix("Location:") {
            siteDir = line
                .replacingOccurrences(of: "Location:", with: "")
                .trimmingCharacters(in: .whitespaces)
            break
        }
    }
    guard !siteDir.isEmpty,
          let entries = try? FileManager.default.contentsOfDirectory(atPath: siteDir)
    else { return [] }

    var findings: [ThreatFinding] = []
    for entry in entries where entry.hasSuffix(".pth") {
        let path = siteDir + "/" + entry
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
        // Lines beginning with "import " are executed, not treated as paths
        let codeLines = content.components(separatedBy: "\n")
            .filter { $0.hasPrefix("import ") }
        guard !codeLines.isEmpty else { continue }
        let preview = codeLines.first ?? ""
        findings.append(ThreatFinding(
            category:    .python,
            severity:    .high,
            title:       "Python .pth executes code on every startup: \(entry)",
            detail:      "'\(entry)' contains executable import statements (\(preview.prefix(80))). Any .pth file with 'import' lines runs that code every time Python is launched — equivalent to a Python-level Launch Agent. Malicious packages use this for persistence and data exfiltration.",
            source:      .localAnalysis,
            location:    path,
            cveIDs:      [],
            remediation: "Inspect \(path). If you don't recognise this file or its contents, remove it with: rm '\(path)'"
        ))
    }
    return findings
}

// MARK: - Layer 2: Package list helpers

private struct SimplePackage { let name: String; let version: String }

private func getPipPackages(pipPath: String) -> [SimplePackage] {
    let out = shell(pipPath, ["list", "--format=json"])
    guard !out.isEmpty,
          let data = out.data(using: .utf8),
          let arr = try? JSONDecoder().decode([[String: String]].self, from: data) else { return [] }
    return arr.compactMap {
        guard let name = $0["name"], let ver = $0["version"] else { return nil }
        return SimplePackage(name: name, version: ver)
    }
}

private func getNpmPackages(npmPath: String) -> [SimplePackage] {
    let out = shell(npmPath, ["ls", "-g", "--json", "--depth=0"])
    guard !out.isEmpty,
          let data = out.data(using: .utf8),
          let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let deps = root["dependencies"] as? [String: Any] else { return [] }
    return deps.compactMap { name, val in
        guard let info = val as? [String: Any], let ver = info["version"] as? String else { return nil }
        return SimplePackage(name: name, version: ver)
    }
}

// MARK: - Layer 2: OSV findings builder

private func buildOSVFindings(from vulnMap: [String: [OSVClient.Vulnerability]], ecosystem: String, totalScanned: Int) -> [ThreatFinding] {
    let cat: ThreatCategory = ecosystem == "PyPI" ? .python : .npm
    return vulnMap.flatMap { pkgName, vulns in
        vulns.map { v in
            let detail = v.details ?? v.summary

            // ── Confirmed malicious package (OSSF feed) ──────────────────
            // OSV IDs from the OSSF malicious-packages dataset are prefixed MAL-
            if v.id.hasPrefix("MAL-") {
                let uninstallCmd = ecosystem == "PyPI"
                    ? "pip3 uninstall -y \(pkgName)"
                    : "npm uninstall -g \(pkgName)"
                return ThreatFinding(
                    category:      cat,
                    severity:      .critical,
                    title:         "Confirmed malicious package: \(pkgName)",
                    detail:        detail,
                    source:        .ossfMalicious,
                    location:      pkgName,
                    cveIDs:        v.cveIDs,
                    remediation:   "This package has been confirmed as malicious by the Open Source Security Foundation (OSSF).\n\nUninstall immediately:\n\(uninstallCmd)",
                    fixCommand:    uninstallCmd,
                    references:    v.references,
                    publishedDate: v.publishedDate,
                    fixedVersion:  nil
                )
            }

            // ── Known CVE vulnerability ───────────────────────────────────
            let ids = v.cveIDs.isEmpty ? v.id : v.cveIDs.joined(separator: ", ")
            var remediation = ecosystem == "PyPI"
                ? "Upgrade with: pip3 install --upgrade \(pkgName)"
                : "Upgrade with: npm update -g \(pkgName)"
            if let fixed = v.fixedVersion {
                remediation += "\n\nFixed in version \(fixed)."
            }

            return ThreatFinding(
                category:      cat,
                severity:      v.severity,
                title:         "\(pkgName) — \(ids)",
                detail:        detail,
                source:        .osv,
                location:      pkgName,
                cveIDs:        v.cveIDs,
                remediation:   remediation,
                fixCommand:    ecosystem == "PyPI"
                    ? "pip3 install --upgrade \(pkgName)"
                    : "npm update -g \(pkgName)",
                references:    v.references,
                publishedDate: v.publishedDate,
                fixedVersion:  v.fixedVersion
            )
        }
    }
}

// MARK: - Layer 3: pip-audit

private func runPipAudit(path: String) -> [ThreatFinding] {
    let out = shell(path, ["--format", "json", "--progress-spinner", "off"])
    guard !out.isEmpty,
          let data = out.data(using: .utf8),
          let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }

    return arr.compactMap { entry -> ThreatFinding? in
        guard let name    = entry["name"]    as? String,
              let version = entry["version"] as? String,
              let vulns   = entry["vulns"]   as? [[String: Any]],
              !vulns.isEmpty else { return nil }

        let ids = vulns.compactMap { $0["id"] as? String }
        let desc = vulns.first?["description"] as? String ?? "Known vulnerability"
        return ThreatFinding(
            category:    .python,
            severity:    .high,
            title:       "\(name)@\(version) — \(ids.first ?? "advisory")",
            detail:      desc,
            source:      .pipAudit,
            location:    name,
            cveIDs:      ids,
            remediation: "Upgrade with: pip3 install --upgrade \(name)",
            fixCommand:  "pip3 install --upgrade \(name)"
        )
    }
}

// MARK: - Shell helper (nonisolated, synchronous)

@discardableResult
private func shell(_ executable: String, _ args: [String]) -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = args
    task.environment = [
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError  = Pipe()
    do {
        try task.run()
        task.waitUntilExit()
    } catch { return "" }
    return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
}
