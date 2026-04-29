# mergen — AI Context Map

> **Stack:** swiftui, go-net-http | none | unknown | mixed
> **Monorepo:** mergen-cli, mergen.xcodeproj

> 0 routes | 0 models | 24 components | 7 lib files | 0 env vars | 0 middleware
> **Token savings:** this file is ~1,900 tokens. Without it, AI exploration would cost ~15,400 tokens. **Saves ~13,600 tokens per conversation.**
> **Last scanned:** 2026-04-29 23:40 — re-run after significant changes

---

# Components

- **ContentView** [client] — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **ResultsTopBar** [client] — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **WelcomeView** [client] — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **FeatureCard** [client] — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **FixAllSheet** [client] — props: scanManager, fixable, adminCount, userCount, isFixing, hasFailures, result, isFixed, isCancelled, rowIcon — `mergen\view\FixAllSheet.swift`
- **FixRowItem** [client] — props: scanManager, fixable, adminCount, userCount, isFixing, hasFailures, result, isFixed, isCancelled, rowIcon — `mergen\view\FixAllSheet.swift`
- **LogViewerSheet** [client] — props: lines, filter, keyword, color, filtered, lineColor, timestamp, body_ — `mergen\view\LogViewerSheet.swift`
- **LogLine** [client] — props: lines, filter, keyword, color, filtered, lineColor, timestamp, body_ — `mergen\view\LogViewerSheet.swift`
- **ResultsListView** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **FilterSortBar** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **FilterPill** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **ScanProgressBanner** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **ExportButtons** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **EmptyFilterView** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SectionHeader** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **StatusBadge** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **VulnerabilityRow** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SeverityDistributionBar** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SevLegendDot** [client] — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **DetailPanelView** [client] — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **EmptyDetailView** [client] — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **VulnerabilityDetailView** [client] — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **AutoFixButton** [client] — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **BadgeView** [client] — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`

---

# Libraries

- `mergen-cli\cmd\root.go` — function SetVersion: (v string), function Execute: ()
- `mergen-cli\internal\checks\registry.go`
  - function Register: (c Check)
  - function All: () []Check
  - function ByCategory: (cat string) []Check
  - function BySection: (sec string) []Check
- `mergen-cli\internal\checks\types.go`
  - class Result
  - class FixInfo
  - class CheckResult
  - interface Check
- `mergen-cli\internal\output\printer.go`
  - function PrintBanner: ()
  - function StatusBadge: (s checks.Status) string
  - function StatusIcon: (s checks.Status) string
  - function PrintCheckResult: (cr checks.CheckResult)
  - function PrintSectionHeader: (section, title string, count int)
  - function PrintProgress: (done, total int) string
  - _...4 more_
- `mergen-cli\internal\output\styles.go` — function SeverityColor: (sev string) lipgloss.Style
- `mergen-cli\internal\report\report.go` — function JSON: (results []checks.CheckResult) ([]byte, error), function HTML: (results []checks.CheckResult) string
- `mergen-cli\internal\runner\runner.go` — function Run: (cs []checks.Check, workers int) <-chan Progress, class Progress

---

# Dependency Graph

## Most Imported Files (change these carefully)

- `os/exec` — imported by **3** files
- `unicode/utf8` — imported by **1** files
- `encoding/json` — imported by **1** files

## Import Map (who imports what)

- `os/exec` ← `mergen-cli\cmd\fix.go`, `mergen-cli\cmd\tui.go`, `mergen-cli\internal\checks\helpers.go`
- `unicode/utf8` ← `mergen-cli\internal\output\printer.go`
- `encoding/json` ← `mergen-cli\internal\report\report.go`

---

_Generated by [codesight](https://github.com/Houseofmvps/codesight) — see your codebase clearly_