# UI

> **Navigation aid.** Component inventory and prop signatures extracted via AST. Read the source files before adding props or modifying component logic.

**24 components** (unknown)

## Client Components

- **ContentView** — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **ResultsTopBar** — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **WelcomeView** — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **FeatureCard** — props: selectedVulnerability, isWelcome, scanManager, automated, passCount, failCount, warnCount, score, fixable, scoreColor — `mergen\ContentView.swift`
- **FixAllSheet** — props: scanManager, fixable, adminCount, userCount, isFixing, hasFailures, result, isFixed, isCancelled, rowIcon — `mergen\view\FixAllSheet.swift`
- **FixRowItem** — props: scanManager, fixable, adminCount, userCount, isFixing, hasFailures, result, isFixed, isCancelled, rowIcon — `mergen\view\FixAllSheet.swift`
- **LogViewerSheet** — props: lines, filter, keyword, color, filtered, lineColor, timestamp, body_ — `mergen\view\LogViewerSheet.swift`
- **LogLine** — props: lines, filter, keyword, color, filtered, lineColor, timestamp, body_ — `mergen\view\LogViewerSheet.swift`
- **ResultsListView** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **FilterSortBar** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **FilterPill** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **ScanProgressBanner** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **ExportButtons** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **EmptyFilterView** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SectionHeader** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **StatusBadge** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **VulnerabilityRow** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SeverityDistributionBar** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **SevLegendDot** — props: id, icon, color, scanManager, selectedVulnerability, searchText, statusFilter, sortOrder, base, results — `mergen\view\ScanResultView.swift`
- **DetailPanelView** — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **EmptyDetailView** — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **VulnerabilityDetailView** — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **AutoFixButton** — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`
- **BadgeView** — props: scanManager, statusColor, statusIcon, statusLabel, severityColor, hasShellCommands, isFixing, result, isFixed, isCancelled — `mergen\view\VulnerabilityDetailView.swift`

---
_Back to [overview.md](./overview.md)_