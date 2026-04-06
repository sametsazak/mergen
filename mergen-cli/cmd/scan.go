package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sametsazak/mergen-cli/internal/checks"
	"github.com/sametsazak/mergen-cli/internal/output"
	"github.com/sametsazak/mergen-cli/internal/runner"
)

var (
	flagSection  string
	flagCategory string
	flagFailed   bool
	flagWorkers  int
	flagQuiet    bool
	flagJSON     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security checks",
	Long: `Audit your Mac against CIS Benchmark controls.

Examples:
  mergen scan                   # run all checks
  mergen scan --section 2       # only section 2 (System Settings)
  mergen scan --failed          # print only failures
  mergen scan --quiet           # summary only, no per-check output
  mergen scan --json            # machine-readable output`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output.PrintBanner()

		// Select checks
		var cs []checks.Check
		switch {
		case flagSection != "":
			cs = checks.BySection(flagSection)
			if len(cs) == 0 {
				return fmt.Errorf("no checks found for section %q", flagSection)
			}
		case flagCategory != "":
			cs = checks.ByCategory(flagCategory)
			if len(cs) == 0 {
				return fmt.Errorf("no checks found for category %q", flagCategory)
			}
		default:
			cs = checks.All()
		}

		total := len(cs)
		fmt.Printf("  %s  Running %s checks on macOS…\n\n",
			output.Accent.Render("→"),
			output.Bold.Render(fmt.Sprintf("%d", total)),
		)

		// Print section header tracker
		sectionNames := map[string]string{
			"1": "Software Updates",
			"2": "System Settings",
			"3": "Logging & Auditing",
			"4": "Network",
			"5": "Auth & Authorization",
			"6": "User Interface",
			"":  "Additional Checks",
		}

		results := make([]checks.CheckResult, 0, total)
		progress := runner.Run(cs, flagWorkers)

		// Collect and display results as they arrive
		// Buffer by section for ordered output
		buf := map[string][]checks.CheckResult{}
		sectionOrder := []string{"1", "2", "3", "4", "5", "6", ""}

		for p := range progress {
			id := p.Result.Check.CISID()
			sec := ""
			if id != "" {
				parts := strings.SplitN(id, ".", 2)
				if len(parts) > 0 {
					sec = parts[0]
				}
			}
			buf[sec] = append(buf[sec], p.Result)
			results = append(results, p.Result)

			if !flagQuiet && !flagJSON {
				fmt.Printf("\r\033[K%s", output.PrintProgress(p.Done, p.Total))
			}
		}
		fmt.Print("\r\033[K") // clear progress line

		if flagJSON {
			printJSONResults(results)
			return nil
		}

		if !flagQuiet {
			// Print results ordered by section
			for _, sec := range sectionOrder {
				items, ok := buf[sec]
				if !ok || len(items) == 0 {
					continue
				}
				// Sort items within section by CIS ID
				sort.Slice(items, func(i, j int) bool {
					return items[i].Check.CISID() < items[j].Check.CISID()
				})

				name := sectionNames[sec]
				if sec == "" {
					name = "Additional Checks"
				}
				output.PrintSectionHeader(sec, name, len(items))

				for _, r := range items {
					if flagFailed && r.Result.Status != checks.StatusFail {
						continue
					}
					output.PrintCheckResult(r)
				}

			}
		}

		output.PrintSummary(results)

		// Exit code 1 if any failures
		for _, r := range results {
			if r.Result.Status == checks.StatusFail {
				os.Exit(1)
			}
		}
		return nil
	},
}

func printJSONResults(results []checks.CheckResult) {
	fmt.Println("[")
	for i, r := range results {
		comma := ","
		if i == len(results)-1 {
			comma = ""
		}
		fmt.Printf(`  {"cis_id":%q,"name":%q,"status":%q,"output":%q}%s`+"\n",
			r.Check.CISID(), r.Check.Name(), r.Result.Status.String(), r.Result.Output, comma)
	}
	fmt.Println("]")
}

func init() {
	scanCmd.Flags().StringVarP(&flagSection, "section", "s", "", "Run only checks in a specific section (1-6)")
	scanCmd.Flags().StringVarP(&flagCategory, "category", "c", "", "Run only checks in a category (e.g. 'CIS Benchmark')")
	scanCmd.Flags().BoolVarP(&flagFailed, "failed", "f", false, "Show only failed checks")
	scanCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 8, "Number of parallel check workers")
	scanCmd.Flags().BoolVarP(&flagQuiet, "quiet", "q", false, "Print summary only")
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")
	rootCmd.AddCommand(scanCmd)
}
