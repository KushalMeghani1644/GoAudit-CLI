package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/analyzer"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/project"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
	"github.com/spf13/cobra"
)

var (
	upgradeMode       string
	managerOverride   string
	includeTransitive bool
	probeAll          bool
	mountProject      bool
	// failOn is defined in scan.go (shared across scan commands).
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
			report.NewReporter(ciMode, verbose).Fatal(err)
		}

		proj, err := project.Open(args[0], managerOverride)
		if err != nil {
			report.NewReporter(ciMode, verbose).Fatal(err)
		}

		installCmd, err := project.BuildInstallCommand(proj.Manager, mode)
		if err != nil {
			report.NewReporter(ciMode, verbose).Fatal(err)
		}

		reporter := report.NewReporter(ciMode, verbose)

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
			reporter.Fatal(err)
		}

		if !ciMode && len(deps) > 0 {
			fmt.Printf("Running static registry checks on %d package(s)...\n", len(deps))
		}

		registryFindings := analyzer.AnalyzeRegistryPackages(deps, proj.Manager)
		findings = append(findings, registryFindings...)
		for _, f := range registryFindings {
			reporter.PrintLiveFinding(f)
		}

		// Determine which packages to probe at runtime.
		var probePackages []string
		if !skipProbe {
			if probeAll {
				probePackages = deps
			} else {
				// Probe only packages that had suspicious static findings.
				suspicious := map[string]bool{}
				for _, f := range registryFindings {
					if f.Severity == report.SeverityWarning || f.Severity == report.SeverityCritical {
						name := extractFindingPackageName(f.Path)
						if name != "" {
							suspicious[name] = true
						}
					}
				}
				for pkg := range suspicious {
					probePackages = append(probePackages, pkg)
				}
				if len(probePackages) == 0 {
					if !ciMode {
						fmt.Println("No suspicious packages from registry checks; skipping runtime probe (use --probe-all to probe all deps)")
					}
				} else if !ciMode {
					fmt.Printf("Probing %d suspicious package(s) at runtime\n", len(probePackages))
				}
			}
		}

		// Stage a sanitized tree so install scripts cannot read real project secrets
		// via /project-ro (bind-mount remains readable for the whole scan).
		stage, err := project.StageForSandbox(proj.Root, project.StageOptions{FullTree: mountProject})
		if err != nil {
			reporter.Fatal(err)
		}
		if mountProject {
			f := report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "policy",
				ReasonCode: "PROJECT_TREE_STAGED",
				Path:       proj.Root,
				Confidence: 90,
				Evidence:   "Full project tree staged into sandbox with secret-path redaction; prefer default minimal staging when possible",
			}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
		} else if !ciMode {
			fmt.Println("Staging minimal install inputs (package.json/lockfiles); use --mount-project for full tree with secret redaction")
		}

		profile := profileForManager(proj.Manager)
		if warmCache {
			err := warmSandboxCache(context.Background(), profile, reporter, pipelineOptions{
				projectPath:     proj.Root,
				scanProjectMode: true,
				probePackages:   probePackages,
				skipProbe:       skipProbe,
			})
			stage.Cleanup()
			if err != nil {
				reporter.Fatal(err)
			}
			return
		}

		fail, err := runScanPipeline(context.Background(), installCmd, profile, reporter, pipelineOptions{
			projectPath:     stage.Dir,
			skipStatic:      true,
			priorFindings:   findings,
			scanProjectMode: true,
			probePackages:   probePackages,
			skipProbe:       skipProbe,
			targetTimeout:   targetTimeout,
			probeTimeout:    probeTimeout,
		})
		stage.Cleanup()
		if err != nil {
			reporter.Fatal(err)
		}
		if fail {
			os.Exit(1)
		}
	},
}

// extractFindingPackageName extracts a bare package name from a finding path
// which may be "pkg@version", "@scope/pkg@version", or just "pkg".
func extractFindingPackageName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	// Handle @scope/pkg@version or @scope/pkg
	if strings.HasPrefix(path, "@") {
		if idx := strings.LastIndex(path, "@"); idx > 0 {
			return path[:idx]
		}
		return path
	}
	// Handle pkg@version
	if idx := strings.Index(path, "@"); idx > 0 {
		return path[:idx]
	}
	return path
}

func init() {
	scanProjectCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanProjectCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show live findings during scan")
	scanProjectCmd.Flags().IntVar(&maxRemoteDepth, "max-remote-depth", 2, "Max recursion depth when fetching staged remote scripts")
	scanProjectCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable remote URL/script fetching during static analysis")
	scanProjectCmd.Flags().StringSliceVar(&allowedDomains, "allow-domain", nil, "Allowlist domains for remote script fetches (repeatable)")
	scanProjectCmd.Flags().StringVar(&nodeImage, "node-image", "node:current-slim", "Node.js image used for npm/pnpm scans")
	scanProjectCmd.Flags().StringVar(&bunImage, "bun-image", "oven/bun:1", "Bun image used for bun scans")
	scanProjectCmd.Flags().StringVar(&networkMode, "network", "auto", "Network policy: auto (based on command type), on, or off")
	scanProjectCmd.Flags().BoolVar(&skipProbe, "skip-probe", false, "Skip runtime behavior probe after install")
	scanProjectCmd.Flags().BoolVar(&warmCache, "warm-cache", false, "Prepare and cache the sandbox without running a scan")
	scanProjectCmd.Flags().BoolVar(&probeAll, "probe-all", false, "Probe all direct dependencies, not just suspicious ones")
	scanProjectCmd.Flags().StringVar(&targetTimeout, "timeout", "", "Maximum time for the install/target command (default: profile-based)")
	scanProjectCmd.Flags().StringVar(&probeTimeout, "probe-timeout", "30s", "Maximum time for runtime import probe")
	scanProjectCmd.Flags().StringVar(&upgradeMode, "upgrade-mode", "refresh-lock", "Upgrade strategy: refresh-lock, ncu, or update")
	scanProjectCmd.Flags().StringVar(&managerOverride, "manager", "", "Force package manager: npm, pnpm, or bun")
	scanProjectCmd.Flags().BoolVar(&includeTransitive, "include-transitive", false, "Also registry-check packages from the manager's lockfile (package-lock.json, pnpm-lock.yaml, or bun.lock)")
	scanProjectCmd.Flags().BoolVar(&mountProject, "mount-project", false, "Stage full project tree into the sandbox (secret paths redacted); default stages only manifests/lockfiles")
	scanProjectCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable sandbox caching for this run (no warm container is stored)")
	scanProjectCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Custom directory for sandbox cache (or set GOAUDIT_CACHE_DIR)")
	scanProjectCmd.Flags().StringVar(&failOn, "fail-on", "never", "Exit non-zero on: never, malicious, inconclusive, or malicious,inconclusive")
	rootCmd.AddCommand(scanProjectCmd)
}
