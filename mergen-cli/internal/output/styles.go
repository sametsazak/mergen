package output

import "github.com/charmbracelet/lipgloss"

// Palette
var (
	colPass    = lipgloss.Color("#22c55e") // green
	colFail    = lipgloss.Color("#ef4444") // red
	colWarn    = lipgloss.Color("#f97316") // orange
	colManual  = lipgloss.Color("#3b82f6") // blue
	colError   = lipgloss.Color("#9ca3af") // grey
	colMuted   = lipgloss.Color("#6b7280")
	colBright  = lipgloss.Color("#f9fafb")
	colAccent  = lipgloss.Color("#a78bfa") // purple
	colBorder  = lipgloss.Color("#374151")
	colHeader  = lipgloss.Color("#1e1b4b")
	colCIS     = lipgloss.Color("#94a3b8")
)

// Status badges
var (
	PassBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(colPass).
			Render("✓ PASS")

	FailBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(colFail).
			Render("✗ FAIL")

	WarnBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(colWarn).
			Render("⚠ WARN")

	ManualBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(colManual).
			Render("ℹ MANUAL")

	ErrorBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(colError).
			Render("? ERROR")
)

// Text styles
var (
	Bold    = lipgloss.NewStyle().Bold(true)
	Muted   = lipgloss.NewStyle().Foreground(colMuted)
	Bright  = lipgloss.NewStyle().Foreground(colBright)
	Accent  = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	CISTag  = lipgloss.NewStyle().Foreground(colCIS)
	PassTxt = lipgloss.NewStyle().Foreground(colPass)
	FailTxt = lipgloss.NewStyle().Foreground(colFail)
	WarnTxt = lipgloss.NewStyle().Foreground(colWarn)
	ManTxt  = lipgloss.NewStyle().Foreground(colManual)
	ErrTxt  = lipgloss.NewStyle().Foreground(colError)
)

// Box styles
var (
	HeaderBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colAccent).
			Padding(0, 2).
			Bold(true)

	SectionBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(colAccent).
			PaddingLeft(1).
			Bold(true).
			Foreground(colBright)

	SummaryBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colBorder).
			Padding(1, 3)

	OutputTxt = lipgloss.NewStyle().
			Foreground(colMuted).
			PaddingLeft(6)

	ProgressBar = lipgloss.NewStyle().
			Foreground(colAccent)
)

// Severity colours
func SeverityColor(sev string) lipgloss.Style {
	switch sev {
	case "Critical":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#dc2626")).Bold(true)
	case "High":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#f97316"))
	case "Medium":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#eab308"))
	case "Low":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#3b82f6"))
	default:
		return lipgloss.NewStyle().Foreground(colMuted)
	}
}
