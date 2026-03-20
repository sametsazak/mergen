package output

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/sametsazak/mergen-cli/internal/checks"
)

const banner = `
  ███╗   ███╗███████╗██████╗  ██████╗ ███████╗███╗   ██╗
  ████╗ ████║██╔════╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║
  ██╔████╔██║█████╗  ██████╔╝██║  ███╗█████╗  ██╔██╗ ██║
  ██║╚██╔╝██║██╔══╝  ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║
  ██║ ╚═╝ ██║███████╗██║  ██║╚██████╔╝███████╗██║ ╚████║
  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝`

// PrintBanner prints the Mergen ASCII logo and subtitle.
func PrintBanner() {
	fmt.Println(Accent.Render(banner))
	fmt.Println(Muted.Render("  macOS Security Audit CLI  ·  CIS Apple macOS 26 Tahoe Benchmark v1.0.0"))
	fmt.Println()
}

// StatusBadge returns the coloured badge for a given status.
func StatusBadge(s checks.Status) string {
	switch s {
	case checks.StatusPass:
		return PassBadge
	case checks.StatusFail:
		return FailBadge
	case checks.StatusWarn:
		return WarnBadge
	case checks.StatusManual:
		return ManualBadge
	default:
		return ErrorBadge
	}
}

// StatusIcon returns a compact single-char symbol.
func StatusIcon(s checks.Status) string {
	switch s {
	case checks.StatusPass:
		return PassTxt.Render("✓")
	case checks.StatusFail:
		return FailTxt.Render("✗")
	case checks.StatusWarn:
		return WarnTxt.Render("⚠")
	case checks.StatusManual:
		return ManTxt.Render("ℹ")
	default:
		return ErrTxt.Render("?")
	}
}

// PrintCheckResult prints a single result line.
func PrintCheckResult(cr checks.CheckResult) {
	c := cr.Check
	r := cr.Result

	// CIS ID column — fixed 9 chars wide, no brackets
	cisID := c.CISID()
	var cisCol string
	if cisID != "" {
		cisCol = CISTag.Render(fmt.Sprintf("%-9s", cisID))
	} else {
		cisCol = strings.Repeat(" ", 9)
	}

	icon := StatusIcon(r.Status)

	name := c.Name()
	maxName := 50
	if utf8.RuneCountInString(name) > maxName {
		runes := []rune(name)
		name = string(runes[:maxName-1]) + "…"
	}

	// Name colour: dim for pass (already resolved), bright for fail/warn/manual
	var nameStyle lipgloss.Style
	switch r.Status {
	case checks.StatusPass:
		nameStyle = Muted
	case checks.StatusFail:
		nameStyle = Bright.Bold(true)
	default:
		nameStyle = Bright
	}

	fmt.Printf("  %s  %s %s\n", icon, cisCol, nameStyle.Render(name))

	// Show detail line for Fail, Warn, and Error
	if r.Output != "" && (r.Status == checks.StatusFail || r.Status == checks.StatusWarn || r.Status == checks.StatusError) {
		msg := r.Output
		// Truncate extremely long messages (e.g. plist dumps)
		const maxMsg = 110
		if utf8.RuneCountInString(msg) > maxMsg {
			runes := []rune(msg)
			msg = string(runes[:maxMsg-1]) + "…"
		}
		fmt.Printf("     %s %s\n", Dim.Render("└─"), OutputTxt.Render(msg))
	}
}

// PrintSectionHeader prints a section divider with optional check count.
func PrintSectionHeader(section, title string, count int) {
	var label string
	if section == "" {
		label = "Additional Checks"
	} else {
		label = fmt.Sprintf("§%s  %s", section, title)
	}

	countHint := ""
	if count > 0 {
		countHint = "  " + Dim.Render(fmt.Sprintf("%d checks", count))
	}

	const ruleLen = 52
	fmt.Println()
	fmt.Printf("  %s%s\n", Accent.Bold(true).Render(label), countHint)
	fmt.Printf("  %s\n", Dim.Render(strings.Repeat("─", ruleLen)))
}

// PrintProgress renders an inline progress bar.
func PrintProgress(done, total int) string {
	if total == 0 {
		return ""
	}
	width := 32
	filled := int(float64(done) / float64(total) * float64(width))
	bar := ProgressBar.Render(strings.Repeat("█", filled)) +
		Dim.Render(strings.Repeat("░", width-filled))
	pct := int(float64(done) / float64(total) * 100)
	return fmt.Sprintf("  %s  %s  %d%%  (%d/%d)",
		bar,
		Dim.Render("scanning"),
		pct, done, total)
}

// PrintSummary prints the final scan summary box.
func PrintSummary(results []checks.CheckResult) {
	var pass, fail, warn, manual int
	for _, r := range results {
		switch r.Result.Status {
		case checks.StatusPass:
			pass++
		case checks.StatusFail:
			fail++
		case checks.StatusWarn:
			warn++
		case checks.StatusManual:
			manual++
		}
	}

	total := len(results)
	automated := pass + fail + warn
	score := 0.0
	if automated > 0 {
		score = float64(pass) / float64(automated) * 100
	}

	var scoreStyle lipgloss.Style
	var scoreLabel string
	switch {
	case score >= 90:
		scoreStyle = PassTxt.Bold(true)
		scoreLabel = PassTxt.Render("Excellent")
	case score >= 75:
		scoreStyle = PassTxt.Bold(true)
		scoreLabel = PassTxt.Render("Good")
	case score >= 50:
		scoreStyle = WarnTxt.Bold(true)
		scoreLabel = WarnTxt.Render("Fair")
	default:
		scoreStyle = FailTxt.Bold(true)
		scoreLabel = FailTxt.Render("Poor")
	}

	// Score bar
	barWidth := 44
	filled := int(score / 100 * float64(barWidth))
	var barColor lipgloss.Color
	switch {
	case score >= 75:
		barColor = colPass
	case score >= 50:
		barColor = colWarn
	default:
		barColor = colFail
	}
	bar := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", filled)) +
		Dim.Render(strings.Repeat("░", barWidth-filled))

	content := fmt.Sprintf(
		"%s  %s  %s\n\n"+
			"  %s  %s pass    %s  %s fail    %s  %s warn    %s  %s info\n\n"+
			"  %s\n"+
			"  %s",
		Accent.Render("Security Score"),
		scoreStyle.Render(fmt.Sprintf("%.0f%%", score)),
		scoreLabel,
		PassTxt.Render("✓"), Bold.Render(fmt.Sprintf("%-3d", pass)),
		FailTxt.Render("✗"), Bold.Render(fmt.Sprintf("%-3d", fail)),
		WarnTxt.Render("⚠"), Bold.Render(fmt.Sprintf("%-3d", warn)),
		ManTxt.Render("ℹ"), Bold.Render(fmt.Sprintf("%-3d", manual)),
		bar,
		Muted.Render(fmt.Sprintf("%d checks total · %d automated · %d advisory", total, automated, manual)),
	)

	fmt.Println()
	fmt.Println(SummaryBox.Render(content))
	fmt.Println()
}

// PrintResults prints all results grouped by section (used by report command).
func PrintResults(results []checks.CheckResult) {
	sections := []struct{ num, title string }{
		{"1", "Software Updates"},
		{"2", "System Settings"},
		{"3", "Logging & Auditing"},
		{"4", "Network"},
		{"5", "Auth & Authorization"},
		{"6", "User Interface"},
		{"", "Additional Checks"},
	}

	bySection := map[string][]checks.CheckResult{}
	for _, r := range results {
		id := r.Check.CISID()
		var key string
		if id != "" {
			parts := strings.SplitN(id, ".", 2)
			key = parts[0]
		}
		bySection[key] = append(bySection[key], r)
	}

	for _, sec := range sections {
		items, ok := bySection[sec.num]
		if !ok || len(items) == 0 {
			continue
		}
		PrintSectionHeader(sec.num, sec.title, len(items))
		for _, r := range items {
			PrintCheckResult(r)
		}
	}
}

// PrintFixableList shows all auto-fixable failed checks.
func PrintFixableList(results []checks.CheckResult) {
	var fixable []checks.CheckResult
	for _, r := range results {
		if r.Result.Status == checks.StatusFail && r.Check.Fix() != nil {
			fixable = append(fixable, r)
		}
	}

	if len(fixable) == 0 {
		fmt.Println(PassTxt.Render("  ✓ No auto-fixable issues found."))
		return
	}

	fmt.Printf("\n  %s  %s\n\n",
		FailTxt.Bold(true).Render(fmt.Sprintf("%d fixable issue(s)", len(fixable))),
		Muted.Render("— run 'mergen fix' to remediate"),
	)

	for _, r := range fixable {
		fi := r.Check.Fix()
		privTag := Muted.Render("[user] ")
		if fi.RequiresAdmin {
			privTag = WarnTxt.Render("[admin]")
		}
		fmt.Printf("  %s %s  %s\n",
			FailTxt.Render("✗"),
			privTag,
			r.Check.Name(),
		)
		if fi.Description != "" {
			fmt.Printf("     %s %s\n", Dim.Render("└─"), OutputTxt.Render(fi.Description))
		}
	}
	fmt.Println()
}

// PrintCheckDetail prints full info for a single check.
func PrintCheckDetail(cr checks.CheckResult) {
	c := cr.Check
	r := cr.Result

	fmt.Println()
	fmt.Printf("  %s  %s\n", StatusBadge(r.Status), Bold.Render(c.Name()))
	if id := c.CISID(); id != "" {
		fmt.Printf("  %s  %s  %s\n",
			CISTag.Render("CIS "+id),
			Muted.Render("·"),
			SeverityColor(c.Severity()).Render(c.Severity()),
		)
	}
	fmt.Println()
	fmt.Println(Muted.Render("  Description"))
	fmt.Printf("     %s\n\n", OutputTxt.Render(c.Description()))
	if r.Output != "" {
		fmt.Println(Muted.Render("  Finding"))
		fmt.Printf("     %s\n\n", OutputTxt.Render(r.Output))
	}
	fmt.Println(Muted.Render("  Remediation"))
	fmt.Printf("     %s\n", OutputTxt.Render(c.Remediation()))
	if fi := c.Fix(); fi != nil {
		fmt.Println()
		privLabel := ManTxt.Render("user-level")
		if fi.RequiresAdmin {
			privLabel = WarnTxt.Render("admin (password required)")
		}
		fmt.Printf("  %s %s\n", Muted.Render("Auto-fix ·"), privLabel)
		fmt.Printf("     %s\n", CISTag.Render("$ "+fi.Command))
	}
	fmt.Println()
}
