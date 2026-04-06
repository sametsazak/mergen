package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mergen",
	Short: "macOS security audit — CIS Apple macOS 26 Tahoe Benchmark",
	Long: `Mergen audits your Mac against 85 CIS Benchmark controls.

  mergen              Launch interactive menu
  mergen scan         Run all security checks
  mergen fix          Fix all auto-fixable failures
  mergen list         List all available checks
  mergen report       Generate HTML or JSON report`,
	SilenceUsage: true,
	// When called with no subcommand, launch the interactive TUI
	RunE: func(cmd *cobra.Command, args []string) error {
		runTUI()
		return nil
	},
}

func SetVersion(v string) {
	rootCmd.Version = v
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
