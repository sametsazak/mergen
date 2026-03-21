package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	tuiAccent  = lipgloss.Color("#a78bfa")
	tuiMuted   = lipgloss.Color("#6b7280")
	tuiSelected = lipgloss.Color("#f9fafb")
	tuiBorder  = lipgloss.Color("#374151")
	tuiGreen   = lipgloss.Color("#22c55e")
	tuiRed     = lipgloss.Color("#ef4444")
	tuiOrange  = lipgloss.Color("#f97316")

	styleBanner = lipgloss.NewStyle().
			Foreground(tuiAccent).
			Bold(true)

	styleSubtitle = lipgloss.NewStyle().
			Foreground(tuiMuted)

	styleMenuCursor = lipgloss.NewStyle().
			Foreground(tuiAccent).
			Bold(true)

	styleMenuSelected = lipgloss.NewStyle().
				Bold(true).
				Foreground(tuiSelected).
				Background(lipgloss.Color("#1e1b4b")).
				PaddingLeft(1).
				PaddingRight(1)

	styleMenuNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#d1d5db")).
			PaddingLeft(1).
			PaddingRight(1)

	styleMenuDesc = lipgloss.NewStyle().
			Foreground(tuiMuted)

	styleShortcut = lipgloss.NewStyle().
			Foreground(tuiAccent)

	styleHelp = lipgloss.NewStyle().
			Foreground(tuiMuted).
			MarginTop(1)

	styleSectionSelected = lipgloss.NewStyle().
				Bold(true).
				Foreground(tuiSelected).
				Background(lipgloss.Color("#1e1b4b")).
				Padding(0, 2)

	styleSectionNormal = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#9ca3af")).
				Padding(0, 2)

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(tuiBorder).
			Padding(1, 3)

	styleTitle = lipgloss.NewStyle().
			Foreground(tuiAccent).
			Bold(true).
			MarginBottom(1)
)

// ── Data ──────────────────────────────────────────────────────────────────────

type menuEntry struct {
	icon    string
	label   string
	desc    string
	shortcut string
	action  string // cobra subcommand or special key
}

var mainMenu = []menuEntry{
	{"⚡", "Scan All Checks", "Run all 85 security checks concurrently", "a", "scan"},
	{"§", "Scan by Section", "Choose a specific CIS section to audit", "s", "section"},
	{"✗", "Show Only Failures", "Scan and display only failing checks", "f", "scan --failed"},
	{"⚙", "Fix Issues", "Auto-remediate all fixable failures", "x", "fix"},
	{"☑", "Dry Run Fix", "Preview fixes without applying them", "d", "fix --dry-run"},
	{"≡", "List All Checks", "Browse every registered check", "l", "list"},
	{"⎘", "Generate HTML Report", "Run scan and export a styled HTML report", "h", "report --format html"},
	{"⎘", "Generate JSON Report", "Run scan and export machine-readable JSON", "j", "report --format json"},
	{"✕", "Quit", "Exit mergen", "q", "quit"},
}

var sections = []struct{ num, label string }{
	{"1", "§1  Software Updates"},
	{"2", "§2  System Settings"},
	{"3", "§3  Logging & Auditing"},
	{"4", "§4  Network"},
	{"5", "§5  Auth & Authorization"},
	{"6", "§6  User Interface"},
}

// ── Model ─────────────────────────────────────────────────────────────────────

type screen int

const (
	screenMain screen = iota
	screenSection
)

type tuiModel struct {
	screen      screen
	cursor      int
	secCursor   int
	chosen      string // set when user makes a selection
	quitting    bool
}

func initialModel() tuiModel {
	return tuiModel{screen: screenMain}
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		key := msg.String()

		// ── Section picker ────────────────────────────────────
		if m.screen == screenSection {
			switch key {
			case "up", "k":
				if m.secCursor > 0 {
					m.secCursor--
				}
			case "down", "j":
				if m.secCursor < len(sections)-1 {
					m.secCursor++
				}
			case "enter", " ":
				m.chosen = "scan --section " + sections[m.secCursor].num
				return m, tea.Quit
			case "esc", "b":
				m.screen = screenMain
			case "q", "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}

		// ── Main menu ─────────────────────────────────────────
		switch key {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(mainMenu)-1 {
				m.cursor++
			}
		case "enter", " ":
			item := mainMenu[m.cursor]
			if item.action == "quit" {
				m.quitting = true
				return m, tea.Quit
			}
			if item.action == "section" {
				m.screen = screenSection
				return m, nil
			}
			m.chosen = item.action
			return m, tea.Quit

		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		default:
			// Shortcut keys
			for _, item := range mainMenu {
				if key == item.shortcut {
					if item.action == "quit" {
						m.quitting = true
						return m, tea.Quit
					}
					if item.action == "section" {
						m.screen = screenSection
						return m, nil
					}
					m.chosen = item.action
					return m, tea.Quit
				}
			}
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.chosen != "" || m.quitting {
		return ""
	}

	var b strings.Builder

	// Banner
	b.WriteString(styleBanner.Render(`
  ███╗   ███╗███████╗██████╗  ██████╗ ███████╗███╗   ██╗
  ████╗ ████║██╔════╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║
  ██╔████╔██║█████╗  ██████╔╝██║  ███╗█████╗  ██╔██╗ ██║
  ██║╚██╔╝██║██╔══╝  ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║
  ██║ ╚═╝ ██║███████╗██║  ██║╚██████╔╝███████╗██║ ╚████║
  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝`))
	b.WriteString("\n")
	b.WriteString(styleSubtitle.Render("  macOS Security Audit  ·  CIS Apple macOS 26 Tahoe Benchmark v1.0.0"))
	b.WriteString("\n\n")

	if m.screen == screenSection {
		return b.String() + m.sectionView()
	}
	return b.String() + m.mainMenuView()
}

func (m tuiModel) mainMenuView() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("  What would you like to do?\n"))

	for i, item := range mainMenu {
		cursor := "  "
		var label string

		if i == m.cursor {
			cursor = styleMenuCursor.Render(" ▶")
			label = styleMenuSelected.Render(
				fmt.Sprintf("%s  %-28s", item.icon, item.label),
			)
		} else {
			label = styleMenuNormal.Render(
				fmt.Sprintf("%s  %-28s", item.icon, item.label),
			)
		}

		shortcut := styleShortcut.Render("[" + item.shortcut + "]")
		desc := styleMenuDesc.Render(item.desc)

		b.WriteString(fmt.Sprintf("%s %s  %s  %s\n", cursor, label, shortcut, desc))
	}

	b.WriteString(styleHelp.Render("\n  ↑↓ / jk navigate  ·  enter select  ·  shortcut key  ·  q quit"))
	b.WriteString("\n")
	return b.String()
}

func (m tuiModel) sectionView() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("  Select a section to scan:\n"))

	for i, sec := range sections {
		cursor := "  "
		var label string

		if i == m.secCursor {
			cursor = styleMenuCursor.Render(" ▶")
			label = styleSectionSelected.Render(sec.label)
		} else {
			label = styleSectionNormal.Render(sec.label)
		}
		b.WriteString(fmt.Sprintf("%s %s\n", cursor, label))
	}

	b.WriteString(styleHelp.Render("\n  ↑↓ navigate  ·  enter select  ·  esc / b back  ·  q quit"))
	b.WriteString("\n")
	return b.String()
}

// ── Entry point ───────────────────────────────────────────────────────────────

func runTUI() {
	p := tea.NewProgram(initialModel())
	result, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}

	m, ok := result.(tuiModel)
	if !ok || m.quitting || m.chosen == "" {
		return
	}

	// Re-exec ourselves with the chosen subcommand args
	args := strings.Fields(m.chosen)
	self, _ := os.Executable()
	cmd := exec.Command(self, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
