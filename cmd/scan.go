package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/analyzer"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/project"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/sandbox"
	"github.com/spf13/cobra"
)

var (
	ciMode        bool
	verbose       bool
	offlineMode   bool
	nodeImage     string
	bunImage      string
	networkMode   string
	runtimeProbe  bool
	skipProbe     bool
	noCache       bool
	warmCache     bool
	cacheDir      string
	targetTimeout string
	probeTimeout  string
	failOn        string
	mountCwd      bool
)

type scanProfile struct {
	Name          string
	Image         string
	RequiredTools []string
	SetupCommands []string
}

var scanCmd = &cobra.Command{
	Use:   "scan <install-command>",
	Short: "Scan an npm, pnpm, or bun install command in a gVisor sandbox",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("an npm, pnpm, or bun install command is required")
		}
		return validateInstallCommand(strings.Join(args, " "))
	},
	PreRunE: validateRuntimeProbeFlags,
	Run: func(cmd *cobra.Command, args []string) {
		targetCmd := strings.Join(args, " ")
		profile := inferProfile(targetCmd)
		reporter := report.NewReporter(ciMode, verbose)

		probePackages := requestedProbePackages(targetCmd, runtimeProbe)

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

func requestedProbePackages(command string, enabled bool) []string {
	if !enabled {
		return nil
	}
	return analyzer.ExtractPackageNamesFromCommand(command)
}

func validateRuntimeProbeFlags(cmd *cobra.Command, _ []string) error {
	enabled, err := cmd.Flags().GetBool("runtime-probe")
	if err != nil {
		return err
	}
	skip, err := cmd.Flags().GetBool("skip-probe")
	if err != nil {
		return err
	}
	if enabled && skip {
		return fmt.Errorf("--runtime-probe and --skip-probe cannot both be true")
	}
	return nil
}

func addRuntimeProbeFlags(cmd *cobra.Command, scope string) {
	cmd.Flags().BoolVar(&runtimeProbe, "runtime-probe", false, "Enable post-install runtime probing of "+scope+" (off by default)")
	cmd.Flags().BoolVar(&skipProbe, "skip-probe", false, "Deprecated compatibility no-op; runtime probing is off by default")
	_ = cmd.Flags().MarkDeprecated("skip-probe", "runtime probing is off by default; remove this flag (use --runtime-probe to opt in)")
}

func validateInstallCommand(command string) error {
	fields := strings.Fields(command)
	if len(fields) < 2 {
		return fmt.Errorf("unsupported scan command %q: use an npm, pnpm, or bun install command", command)
	}

	// The command runs in a sandbox, but scan intentionally accepts one package
	// manager invocation rather than a shell program or command chain.
	if strings.ContainsAny(command, ";&|<>\n\r`") || strings.Contains(command, "$(") {
		return fmt.Errorf("unsupported scan command %q: shell operators are not allowed", command)
	}

	manager := fields[0]
	subcommand := fields[1]
	allowed := false
	switch manager {
	case "npm":
		allowed = subcommand == "install" || subcommand == "i" || subcommand == "add"
	case "pnpm":
		allowed = subcommand == "install" || subcommand == "i" || subcommand == "add"
	case "bun":
		allowed = subcommand == "install" || subcommand == "add"
	}
	if !allowed {
		return fmt.Errorf("unsupported scan command %q: use npm, pnpm, or bun with install/add (npm and pnpm also support i)", command)
	}
	return nil
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
	switch strings.Fields(cmd)[0] {
	case "pnpm":
		return profileForManager("pnpm")
	case "bun":
		return profileForManager("bun")
	default:
		return profileForManager("npm")
	}
}

func init() {
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show live findings during scan (default: only final report)")
	scanCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable npm registry requests during static analysis")
	scanCmd.Flags().StringVar(&nodeImage, "node-image", sandbox.DefaultNodeImage, "Node.js image used for npm/pnpm scans")
	scanCmd.Flags().StringVar(&bunImage, "bun-image", sandbox.DefaultBunImage, "Bun image used for bun scans")
	scanCmd.Flags().StringVar(&networkMode, "network", "auto", "Network policy: auto (based on command type), on, or off")
	addRuntimeProbeFlags(scanCmd, "packages named in the install command")
	scanCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable sandbox caching for this run (no warm container is stored)")
	scanCmd.Flags().BoolVar(&warmCache, "warm-cache", false, "Prepare and cache the sandbox without running a scan")
	scanCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Custom directory for sandbox cache (or set GOAUDIT_CACHE_DIR)")
	scanCmd.Flags().StringVar(&targetTimeout, "timeout", "", "Maximum time for the install/target command (default: profile-based)")
	scanCmd.Flags().StringVar(&probeTimeout, "probe-timeout", "30s", "Maximum time for runtime probe")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "never", "Exit non-zero on: never, malicious, inconclusive, or malicious,inconclusive")
	scanCmd.Flags().BoolVar(&mountCwd, "mount-cwd", false, "Allow mounting the current working directory for multi-local package installs (secret-redacted stage)")
	rootCmd.AddCommand(scanCmd)
}
