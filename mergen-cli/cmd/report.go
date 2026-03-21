package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sametsazak/mergen-cli/internal/checks"
	"github.com/sametsazak/mergen-cli/internal/output"
	"github.com/sametsazak/mergen-cli/internal/report"
	"github.com/sametsazak/mergen-cli/internal/runner"
)

var (
	flagReportFormat string
	flagReportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Run scan and export an HTML or JSON report",
	Long: `Runs a full scan and exports the results.

Examples:
  mergen report                           # HTML to ./mergen-report.html
  mergen report --format json             # JSON to ./mergen-report.json
  mergen report --format html -o out.html # custom output path`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output.PrintBanner()

		fmt.Printf("  %s  Scanning for report…\n\n", output.Accent.Render("→"))

		cs := checks.All()
		total := len(cs)

		var results []checks.CheckResult
		ch := runner.Run(cs, 8)
		for p := range ch {
			results = append(results, p.Result)
			fmt.Printf("\r%s", output.PrintProgress(p.Done, total))
		}
		fmt.Println()

		output.PrintSummary(results)

		// Determine output path
		outPath := flagReportOutput
		format := flagReportFormat

		if outPath == "" {
			switch format {
			case "json":
				outPath = "mergen-report.json"
			default:
				outPath = "mergen-report.html"
				format = "html"
			}
		}
		if format == "" {
			format = "html"
		}

		switch format {
		case "json":
			data, err := report.JSON(results)
			if err != nil {
				return fmt.Errorf("JSON generation failed: %w", err)
			}
			if err := os.WriteFile(outPath, data, 0644); err != nil {
				return fmt.Errorf("could not write %s: %w", outPath, err)
			}
		case "html":
			html := report.HTML(results)
			if err := os.WriteFile(outPath, []byte(html), 0644); err != nil {
				return fmt.Errorf("could not write %s: %w", outPath, err)
			}
		default:
			return fmt.Errorf("unknown format %q — use 'html' or 'json'", format)
		}

		fmt.Printf("  %s  Report saved to %s\n\n",
			output.PassTxt.Render("✓"),
			output.Accent.Render(outPath),
		)
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVarP(&flagReportFormat, "format", "F", "html", "Output format: html or json")
	reportCmd.Flags().StringVarP(&flagReportOutput, "output", "o", "", "Output file path (default: mergen-report.[html|json])")
	rootCmd.AddCommand(reportCmd)
}
