package cmd

import (
	"context"
	"os"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/analyzer"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/project"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
	"github.com/spf13/cobra"
)

var (
	ciMode         bool
	verbose        bool
	maxRemoteDepth int
	offlineMode    bool
	allowedDomains []string
	nodeImage      string
	bunImage       string
	networkMode    string
	skipProbe      bool
	noCache        bool
	warmCache      bool
	cacheDir       string
	targetTimeout  string
	probeTimeout   string
	failOn         string
	mountCwd       bool
)

type scanProfile struct {
	Name          string
	Image         string
	RequiredTools []string
	SetupCommands []string
}

var scanCmd = &cobra.Command{
	Use:   "scan <command>",
	Short: "Scan a command inside a gVisor sandbox",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetCmd := strings.Join(args, " ")
		profile := inferProfile(targetCmd)
		reporter := report.NewReporter(ciMode, verbose)

		var probePackages []string
		if !skipProbe {
			probePackages = analyzer.ExtractPackageNamesFromCommand(targetCmd)
		}

		runtimeTargetCmd, projectPath, localFindings := prepareLocalPackageInstall(targetCmd)

		// When mounting a local package (or CWD), stage a secret-redacted copy so
		// /project-ro never exposes real .env / keys / tokens from the host tree.
		var cleanupStage func()
		if projectPath != "" {
			stage, err := project.StageForSandbox(projectPath, project.StageOptions{FullTree: true})
			if err != nil {
				reporter.Fatal(err)
			}
			cleanupStage = stage.Cleanup
			projectPath = stage.Dir
		}
		cleanup := func() {
			if cleanupStage != nil {
				cleanupStage()
			}
		}

		if warmCache {
			err := warmSandboxCache(context.Background(), profile, reporter, pipelineOptions{
				projectPath:    projectPath,
				runtimeCommand: runtimeTargetCmd,
				probePackages:  probePackages,
				skipProbe:      skipProbe,
			})
			cleanup()
			if err != nil {
				reporter.Fatal(err)
			}
			return
		}

		fail, err := runScanPipeline(context.Background(), targetCmd, profile, reporter, pipelineOptions{
			projectPath:    projectPath,
			runtimeCommand: runtimeTargetCmd,
			priorFindings:  localFindings,
			probePackages:  probePackages,
			skipProbe:      skipProbe,
			targetTimeout:  targetTimeout,
			probeTimeout:   probeTimeout,
		})
		cleanup()
		if err != nil {
			reporter.Fatal(err)
		}
		if fail {
			os.Exit(1)
		}
	},
}

func prepareLocalPackageInstall(targetCmd string) (string, string, []report.Finding) {
	if !analyzer.HasLocalPackageInstall(targetCmd) {
		return targetCmd, "", nil
	}
	if rewritten, path, ok := analyzer.RewriteSingleLocalPackageInstall(targetCmd); ok {
		return rewritten, path, nil
	}
	// Multi/unsupported local specs: refuse CWD mount by default so install scripts
	// cannot read arbitrary host secrets. Opt in with --mount-cwd.
	if !mountCwd {
		return targetCmd, "", []report.Finding{{
			Severity:   report.SeverityWarning,
			Type:       "runtime",
			ReasonCode: "LOCAL_PACKAGE_REWRITE_UNAVAILABLE",
			Path:       targetCmd,
			Confidence: 80,
			Evidence:   "local package install contains multiple or unsupported local path specs; refusing to mount the working directory (pass --mount-cwd to override)",
		}}
	}
	wd, err := os.Getwd()
	if err != nil {
		return targetCmd, "", []report.Finding{localPackageRewriteUnavailableFinding(targetCmd, err.Error())}
	}
	return targetCmd, wd, []report.Finding{
		localPackageRewriteUnavailableFinding(targetCmd, "local package install contains multiple or unsupported local path specs; mounted the current working directory without rewriting the command (--mount-cwd)"),
		{
			Severity:   report.SeverityWarning,
			Type:       "policy",
			ReasonCode: "PROJECT_TREE_STAGED",
			Path:       wd,
			Confidence: 90,
			Evidence:   "Current working directory was copied into a secret-redacted stage and that stage is bind-mounted into the sandbox",
		},
	}
}

func localPackageRewriteUnavailableFinding(targetCmd, evidence string) report.Finding {
	return report.Finding{
		Severity:   report.SeverityWarning,
		Type:       "runtime",
		ReasonCode: "LOCAL_PACKAGE_REWRITE_UNAVAILABLE",
		Path:       targetCmd,
		Confidence: 70,
		Evidence:   evidence,
	}
}

func inferProfile(cmd string) scanProfile {
	lc := strings.ToLower(cmd)
	switch {
	case strings.Contains(lc, "pnpm"):
		return profileForManager("pnpm")
	case strings.Contains(lc, "bun"):
		return profileForManager("bun")
	case strings.Contains(lc, "npm") || strings.Contains(lc, "npx"):
		return profileForManager("npm")
	case strings.Contains(lc, "pip") || strings.Contains(lc, "python"):
		return scanProfile{Name: "python", Image: "python:3.12-slim", RequiredTools: []string{"bash", "strace", "python3", "curl"}}
	case strings.Contains(lc, "curl") || strings.Contains(lc, "bash"):
		return scanProfile{Name: "shell", Image: "ubuntu:24.04", RequiredTools: []string{"bash", "strace", "curl"}}
	default:
		return scanProfile{Name: "default", Image: "ubuntu:24.04", RequiredTools: []string{"bash", "strace", "curl"}}
	}
}

func init() {
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show live findings during scan (default: only final report)")
	scanCmd.Flags().IntVar(&maxRemoteDepth, "max-remote-depth", 2, "Max recursion depth when fetching staged remote scripts")
	scanCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable remote URL/script fetching during static analysis")
	scanCmd.Flags().StringSliceVar(&allowedDomains, "allow-domain", nil, "Allowlist domains for remote script fetches (repeatable)")
	scanCmd.Flags().StringVar(&nodeImage, "node-image", "node:current-slim", "Node.js image used for npm/pnpm scans")
	scanCmd.Flags().StringVar(&bunImage, "bun-image", "oven/bun:1", "Bun image used for bun scans")
	scanCmd.Flags().StringVar(&networkMode, "network", "auto", "Network policy: auto (based on command type), on, or off")
	scanCmd.Flags().BoolVar(&skipProbe, "skip-probe", false, "Skip runtime behavior probe after install")
	scanCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable sandbox caching for this run (no warm container is stored)")
	scanCmd.Flags().BoolVar(&warmCache, "warm-cache", false, "Prepare and cache the sandbox without running a scan")
	scanCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Custom directory for sandbox cache (or set GOAUDIT_CACHE_DIR)")
	scanCmd.Flags().StringVar(&targetTimeout, "timeout", "", "Maximum time for the install/target command (default: profile-based)")
	scanCmd.Flags().StringVar(&probeTimeout, "probe-timeout", "30s", "Maximum time for runtime import probe")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "never", "Exit non-zero on: never, malicious, inconclusive, or malicious,inconclusive")
	scanCmd.Flags().BoolVar(&mountCwd, "mount-cwd", false, "Allow mounting the current working directory for multi-local package installs (secret-redacted stage)")
	rootCmd.AddCommand(scanCmd)
}
