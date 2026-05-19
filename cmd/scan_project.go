package cmd

import (
	"context"
	"fmt"

	"github.com/KushalMeghani1644/goaudit/internal/analyzer"
	"github.com/KushalMeghani1644/goaudit/internal/project"
	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/spf13/cobra"
)

var (
	upgradeMode       string
	managerOverride   string
	includeTransitive bool
)

// Lifecycle reason codes that are expected and noisy in scan-project mode.
var suppressedProjectReasons = map[string]bool{
	"NPM_LIFECYCLE_SCRIPTS":  true,
	"PNPM_LIFECYCLE_SCRIPTS": true,
	"BUN_INSTALL_SCRIPTS":    true,
}

var scanProjectCmd = &cobra.Command{
	Use:   "scan-project <path>",
	Short: "Scan a JS project by upgrading and installing dependencies in a sandbox",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mode, err := project.ParseUpgradeMode(upgradeMode)
		if err != nil {
			report.NewReporter(ciMode).Fatalf("%v\n", err)
		}

		proj, err := project.Open(args[0], managerOverride)
		if err != nil {
			report.NewReporter(ciMode).Fatalf("%v\n", err)
		}

		installCmd, err := project.BuildInstallCommand(proj.Manager, mode)
		if err != nil {
			report.NewReporter(ciMode).Fatalf("%v\n", err)
		}

		reporter := report.NewReporter(ciMode)

		if !ciMode {
			fmt.Printf("Detected package manager: %s\n", proj.Manager)
			fmt.Printf("Upgrade mode: %s\n", mode)
		}

		// Run command-level static analysis, suppressing expected lifecycle warnings.
		var findings []report.Finding
		rawFindings := analyzer.AnalyzeCommand(installCmd)
		for _, f := range rawFindings {
			if suppressedProjectReasons[f.ReasonCode] {
				continue
			}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
		}

		deps, err := proj.ListDepsForStatic(includeTransitive)
		if err != nil {
			reporter.Fatalf("Failed to list dependencies: %v\n", err)
		}

		if !ciMode && len(deps) > 0 {
			fmt.Printf("Running static registry checks on %d package(s)...\n", len(deps))
		}

		registryFindings := analyzer.AnalyzeRegistryPackages(deps, proj.Manager)
		findings = append(findings, registryFindings...)
		for _, f := range registryFindings {
			reporter.PrintLiveFinding(f)
		}

		profile := profileForManager(proj.Manager)
		runScanPipeline(context.Background(), installCmd, profile, reporter, pipelineOptions{
			projectPath:     proj.Root,
			skipStatic:      true,
			priorFindings:   findings,
			scanProjectMode: true,
			runAsRoot:       runAsRoot,
		})
	},
}

func init() {
	scanProjectCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanProjectCmd.Flags().IntVar(&maxRemoteDepth, "max-remote-depth", 2, "Max recursion depth when fetching staged remote scripts")
	scanProjectCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable remote URL/script fetching during static analysis")
	scanProjectCmd.Flags().StringSliceVar(&allowedDomains, "allow-domain", nil, "Allowlist domains for remote script fetches (repeatable)")
	scanProjectCmd.Flags().StringVar(&nodeImage, "node-image", "node:current-slim", "Node.js image used for npm/pnpm scans")
	scanProjectCmd.Flags().StringVar(&bunImage, "bun-image", "oven/bun:1", "Bun image used for bun scans")
	scanProjectCmd.Flags().StringVar(&networkMode, "network", "auto", "Network policy: auto (based on command type), on, or off")
	scanProjectCmd.Flags().BoolVar(&runAsRoot, "run-as-root", false, "Run the target command as root inside the sandbox (default: non-root)")
	scanProjectCmd.Flags().StringVar(&upgradeMode, "upgrade-mode", "refresh-lock", "Upgrade strategy: refresh-lock, ncu, or update")
	scanProjectCmd.Flags().StringVar(&managerOverride, "manager", "", "Force package manager: npm, pnpm, or bun")
	scanProjectCmd.Flags().BoolVar(&includeTransitive, "include-transitive", false, "Also registry-check packages from package-lock.json")
	rootCmd.AddCommand(scanProjectCmd)
}
