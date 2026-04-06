package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sametsazak/mergen-cli/internal/checks"
	"github.com/sametsazak/mergen-cli/internal/output"
	"github.com/sametsazak/mergen-cli/internal/runner"
)

var (
	flagFixID    string
	flagFixAll   bool
	flagFixDryRun bool
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Auto-remediate failed checks",
	Long: `Apply automatic fixes to failing checks.

User-level fixes run immediately. Admin fixes require your password
via the standard macOS authentication dialog.

Examples:
  mergen fix              # scan then fix all auto-fixable failures
  mergen fix --id 2.2.1   # fix one specific check
  mergen fix --dry-run    # show what would be fixed without applying`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output.PrintBanner()

		// Run a full scan first to find failures
		fmt.Printf("  %s  Scanning to find fixable issues…\n\n", output.Accent.Render("→"))

		cs := checks.All()
		results := collectResults(cs)

		var toFix []checks.CheckResult

		if flagFixID != "" {
			// Fix single check by CIS ID
			for _, r := range results {
				if r.Check.CISID() == flagFixID {
					if r.Result.Status != checks.StatusFail {
						fmt.Printf("  %s  Check %s is not failing (%s)\n",
							output.PassTxt.Render("✓"),
							flagFixID,
							r.Result.Status.String(),
						)
						return nil
					}
					if r.Check.Fix() == nil {
						return fmt.Errorf("check %s does not have an auto-fix", flagFixID)
					}
					toFix = append(toFix, r)
					break
				}
			}
			if len(toFix) == 0 {
				return fmt.Errorf("check with CIS ID %q not found", flagFixID)
			}
		} else {
			// All fixable failures
			for _, r := range results {
				if r.Result.Status == checks.StatusFail && r.Check.Fix() != nil {
					toFix = append(toFix, r)
				}
			}
		}

		if len(toFix) == 0 {
			fmt.Println(output.PassTxt.Render("  ✓ No auto-fixable issues found."))
			return nil
		}

		// Show what will be fixed
		fmt.Printf("  %s to fix:\n\n",
			output.FailTxt.Bold(true).Render(fmt.Sprintf("%d issue(s)", len(toFix))),
		)

		var adminFixes []checks.CheckResult
		var userFixes []checks.CheckResult

		for _, r := range toFix {
			fi := r.Check.Fix()
			privTag := output.Muted.Render("[user] ")
			if fi.RequiresAdmin {
				privTag = output.WarnTxt.Render("[admin]")
				adminFixes = append(adminFixes, r)
			} else {
				userFixes = append(userFixes, r)
			}
			fmt.Printf("  %s %s  %s\n",
				output.FailTxt.Render("✗"), privTag, r.Check.Name(),
			)
			if fi.Description != "" {
				fmt.Println(output.OutputTxt.Render("  → " + fi.Description))
			}
		}
		fmt.Println()

		if flagFixDryRun {
			fmt.Println(output.WarnTxt.Render("  Dry run — no changes applied."))
			return nil
		}

		// Confirm
		if !flagFixAll {
			fmt.Print(output.Muted.Render("  Apply fixes? [y/N] "))
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			if !strings.EqualFold(strings.TrimSpace(answer), "y") {
				fmt.Println(output.Muted.Render("  Cancelled."))
				return nil
			}
		}

		// Apply user-level fixes
		for _, r := range userFixes {
			applyFix(r, false)
		}

		// Apply admin fixes (batched via osascript)
		if len(adminFixes) > 0 {
			applyAdminFixes(adminFixes)
		}

		// Re-verify
		fmt.Printf("\n  %s  Re-running fixed checks…\n\n", output.Accent.Render("→"))
		var fixed, stillFailing int
		for _, r := range toFix {
			newResult := r.Check.Run()
			if newResult.Status == checks.StatusPass || newResult.Status == checks.StatusWarn {
				fmt.Printf("  %s  %s\n", output.PassTxt.Render("✓"), r.Check.Name())
				fixed++
			} else {
				fmt.Printf("  %s  %s\n", output.FailTxt.Render("✗"), r.Check.Name())
				if newResult.Output != "" {
					fmt.Println(output.OutputTxt.Render(newResult.Output))
				}
				stillFailing++
			}
		}

		fmt.Println()
		if stillFailing > 0 {
			fmt.Printf("  %s  %d fixed · %s still failing\n",
				output.WarnTxt.Render("⚠"),
				fixed,
				output.FailTxt.Render(fmt.Sprintf("%d", stillFailing)),
			)
		} else {
			fmt.Printf("  %s  All %d issues fixed\n",
				output.PassTxt.Render("✓"),
				fixed,
			)
		}
		fmt.Println()
		return nil
	},
}

func collectResults(cs []checks.Check) []checks.CheckResult {
	var results []checks.CheckResult
	total := len(cs)
	ch := runner.Run(cs, 8)
	for p := range ch {
		results = append(results, p.Result)
		fmt.Printf("\r%s", output.PrintProgress(p.Done, total))
	}
	fmt.Println()
	return results
}

func applyFix(r checks.CheckResult, admin bool) {
	fi := r.Check.Fix()
	fmt.Printf("  %s  Fixing: %s\n", output.Accent.Render("→"), r.Check.Name())
	cmd := exec.Command("/bin/sh", "-c", fi.Command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  %s  %s\n", output.FailTxt.Render("✗"), strings.TrimSpace(string(out)))
	}
}

func applyAdminFixes(adminFixes []checks.CheckResult) {
	fmt.Printf("\n  %s  Applying %d admin fix(es) — macOS will prompt for your password…\n\n",
		output.WarnTxt.Render("⚠"),
		len(adminFixes),
	)

	// Batch all admin commands into one osascript call
	var cmds []string
	for _, r := range adminFixes {
		cmds = append(cmds, r.Check.Fix().Command)
	}
	batched := strings.Join(cmds, " ; ")
	// Wrap in bash -c with exit 0 so individual command failures don't abort
	// the batch — matches the SwiftUI app's FixManager behaviour.
	shellCmd := strings.ReplaceAll(batched, "'", "'\\''")
	bashWrapped := fmt.Sprintf("bash -c '%s; exit 0'", shellCmd)
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`,
		strings.ReplaceAll(bashWrapped, `"`, `\"`))

	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  %s  Admin fix failed: %s\n",
			output.FailTxt.Render("✗"),
			strings.TrimSpace(string(out)),
		)
	}
}

func init() {
	fixCmd.Flags().StringVar(&flagFixID, "id", "", "Fix a single check by CIS ID (e.g. 2.2.1)")
	fixCmd.Flags().BoolVarP(&flagFixAll, "yes", "y", false, "Apply all fixes without confirmation prompt")
	fixCmd.Flags().BoolVar(&flagFixDryRun, "dry-run", false, "Show what would be fixed without applying")
	rootCmd.AddCommand(fixCmd)
}
