package cmd

import (
	"context"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/spf13/cobra"
)

var (
	ciMode         bool
	maxRemoteDepth int
	offlineMode    bool
	allowedDomains []string
	nodeImage      string
	bunImage       string
	networkMode    string
	runAsRoot      bool
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
		reporter := report.NewReporter(ciMode)
		runScanPipeline(context.Background(), targetCmd, profile, reporter, pipelineOptions{
			runAsRoot: runAsRoot,
		})
	},
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
		return scanProfile{
			Name:          "python",
			Image:         "python:3.12-slim",
			RequiredTools: []string{"bash", "strace", "python3", "curl"},
		}
	case strings.Contains(lc, "curl") || strings.Contains(lc, "bash"):
		return scanProfile{
			Name:          "shell",
			Image:         "ubuntu:24.04",
			RequiredTools: []string{"bash", "strace", "curl"},
		}
	default:
		return scanProfile{
			Name:          "default",
			Image:         "ubuntu:24.04",
			RequiredTools: []string{"bash", "strace", "curl"},
		}
	}
}

func init() {
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanCmd.Flags().IntVar(&maxRemoteDepth, "max-remote-depth", 2, "Max recursion depth when fetching staged remote scripts")
	scanCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable remote URL/script fetching during static analysis")
	scanCmd.Flags().StringSliceVar(&allowedDomains, "allow-domain", nil, "Allowlist domains for remote script fetches (repeatable)")
	scanCmd.Flags().StringVar(&nodeImage, "node-image", "node:current-slim", "Node.js image used for npm/pnpm scans")
	scanCmd.Flags().StringVar(&bunImage, "bun-image", "oven/bun:1", "Bun image used for bun scans")
	scanCmd.Flags().StringVar(&networkMode, "network", "auto", "Network policy: auto (based on command type), on, or off")
	scanCmd.Flags().BoolVar(&runAsRoot, "run-as-root", false, "Run the target command as root inside the sandbox (default: non-root)")
	rootCmd.AddCommand(scanCmd)
}
