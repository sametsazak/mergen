package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sametsazak/mergen-cli/internal/checks"
	"github.com/sametsazak/mergen-cli/internal/output"
)

var flagListSection string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available checks",
	Long: `Display all registered security checks with their CIS ID, severity, and fix availability.

Examples:
  mergen list               # list all checks
  mergen list --section 5   # list only Section 5 checks`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output.PrintBanner()

		var cs []checks.Check
		if flagListSection != "" {
			cs = checks.BySection(flagListSection)
			if len(cs) == 0 {
				return fmt.Errorf("no checks found for section %q", flagListSection)
			}
		} else {
			cs = checks.All()
		}

		sectionNames := map[string]string{
			"1": "Software Updates",
			"2": "System Settings",
			"3": "Logging & Auditing",
			"4": "Network",
			"5": "Auth & Authorization",
			"6": "User Interface",
			"":  "Additional Checks",
		}
		sectionOrder := []string{"1", "2", "3", "4", "5", "6", ""}

		// Group by section
		bySection := map[string][]checks.Check{}
		for _, c := range cs {
			id := c.CISID()
			sec := ""
			if id != "" {
				parts := strings.SplitN(id, ".", 2)
				sec = parts[0]
			}
			bySection[sec] = append(bySection[sec], c)
		}

		total := len(cs)
		fmt.Printf("  %s\n\n",
			output.Muted.Render(fmt.Sprintf("%d checks registered", total)),
		)

		for _, sec := range sectionOrder {
			items, ok := bySection[sec]
			if !ok || len(items) == 0 {
				continue
			}
			name := sectionNames[sec]
			if sec == "" {
				sec = "—"
			}
			output.PrintSectionHeader(sec, name)
			fmt.Println()

			for _, c := range items {
				cisTag := output.CISTag.Render(fmt.Sprintf("%-8s", c.CISID()))

				fixTag := output.Muted.Render("       ")
				if c.Fix() != nil {
					if c.Fix().RequiresAdmin {
						fixTag = output.WarnTxt.Render("[admin]")
					} else {
						fixTag = output.ManTxt.Render("[user] ")
					}
				}

				manualTag := ""
				if c.IsManual() {
					manualTag = output.Muted.Render(" [manual]")
				}

				sevStyle := output.SeverityColor(c.Severity())

				fmt.Printf("  %s  %s  %s  %s%s\n",
					cisTag,
					sevStyle.Render(fmt.Sprintf("%-8s", c.Severity())),
					fixTag,
					c.Name(),
					manualTag,
				)
			}
		}

		// Stats footer
		var autoFixable, manual int
		for _, c := range cs {
			if c.Fix() != nil {
				autoFixable++
			}
			if c.IsManual() {
				manual++
			}
		}
		fmt.Printf("\n  %s · %s auto-fixable · %s advisory\n\n",
			output.Muted.Render(fmt.Sprintf("%d total", total)),
			output.PassTxt.Render(fmt.Sprintf("%d", autoFixable)),
			output.ManTxt.Render(fmt.Sprintf("%d", manual)),
		)
		return nil
	},
}

func init() {
	listCmd.Flags().StringVarP(&flagListSection, "section", "s", "", "Filter by section number (1-6)")
	rootCmd.AddCommand(listCmd)
}
