package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/analyzer"
	"github.com/KushalMeghani1644/goaudit/internal/parser"
	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/KushalMeghani1644/goaudit/internal/sandbox"
)

type pipelineOptions struct {
	projectPath     string
	skipStatic      bool
	priorFindings   []report.Finding
	allowNetwork    bool
	runAsRoot       bool
	scanProjectMode bool
}

func runScanPipeline(ctx context.Context, targetCmd string, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) {
	findings := append([]report.Finding{}, opts.priorFindings...)

	if !opts.skipStatic {
		cmdFindings := analyzer.AnalyzeCommand(targetCmd)
		findings = append(findings, cmdFindings...)
		for _, f := range cmdFindings {
			reporter.PrintLiveFinding(f)
		}

		jsFindings := analyzer.AnalyzeJSPackageManagers(targetCmd)
		findings = append(findings, jsFindings...)
		for _, f := range jsFindings {
			reporter.PrintLiveFinding(f)
		}
	}

	if urls := analyzer.ExtractURLs(targetCmd); len(urls) > 0 && !opts.skipStatic {
		if offlineMode {
			f := report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "policy",
				ReasonCode: "INCONCLUSIVE_REMOTE_FETCH",
				Path:       strings.Join(urls, ","),
				Confidence: 35,
				Evidence:   "Offline mode disabled remote script retrieval",
			}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
		} else {
			scriptFindings := analyzer.AnalyzeRemoteScriptsWithPolicy(urls, maxRemoteDepth, allowedDomains)
			findings = append(findings, scriptFindings...)
			for _, f := range scriptFindings {
				reporter.PrintLiveFinding(f)
			}
		}
	}

	// Determine network policy: auto-detect from profile if not explicitly set.
	networkEnabled := opts.allowNetwork
	if networkMode == "auto" {
		switch profile.Name {
		case "npm", "pnpm", "bun":
			networkEnabled = true
			if !ciMode {
				fmt.Printf("Package manager (%s) detected, keeping network ON\n", profile.Name)
			}
		default:
			networkEnabled = false
			if !ciMode {
				fmt.Println("Non-package-manager command detected, network OFF (sandbox isolated)")
			}
		}
	} else if networkMode == "on" {
		networkEnabled = true
	} else if networkMode == "off" {
		networkEnabled = false
	}

	if !ciMode {
		fmt.Printf("Pulling sandbox image %s (one-time setup)...\n", profile.Image)
	}

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: networkEnabled,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
	}

	if err := s.EnsureImage(ctx); err != nil {
		reporter.Fatalf("Failed to pull image: %v\n", err)
	}

	if s.Runtime() != "runsc" && !ciMode {
		fmt.Println("\n\033[33m[WARNING] 'runsc' (gVisor) runtime not found in Docker. Falling back to default runtime (runc).\033[0m")
		fmt.Println("\033[33mFor proper sandboxing, it is highly recommended to install gVisor and configure it in Docker.\033[0m")
		fmt.Println()
	}

	if !ciMode {
		if opts.projectPath != "" {
			fmt.Println("Running project install in sandbox:", targetCmd)
			fmt.Println("Project path:", opts.projectPath)
		} else {
			fmt.Println("Running command in sandbox:", targetCmd)
		}
		if !networkEnabled {
			fmt.Println("Network: \033[32mOFF (isolated)\033[0m")
		} else {
			fmt.Println("Network: \033[33mON\033[0m")
		}
		if opts.runAsRoot {
			fmt.Println("Execution user: \033[33mroot\033[0m")
		} else {
			fmt.Println("Execution user: \033[32msandbox (uid 1000)\033[0m")
		}
	}

	var logStream io.Reader
	if opts.projectPath != "" {
		logStream, err = s.RunProjectCommand(ctx, targetCmd, opts.projectPath, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	} else {
		logStream, err = s.RunCommand(ctx, targetCmd, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	}
	if err != nil {
		s.Cleanup(ctx)
		reporter.Fatalf("Failed to run command: %v\n", err)
	}

	dynamicFindings, err := parser.ParseStream(logStream, reporter)
	if err != nil {
		s.Cleanup(ctx)
		reporter.Fatalf("Failed to parse output: %v\n", err)
	}
	findings = append(findings, dynamicFindings...)

	s.Cleanup(ctx)
	reporter.Report(findings)
}

func profileForManager(manager string) scanProfile {
	switch strings.ToLower(manager) {
	case "pnpm":
		return scanProfile{
			Name:          "pnpm",
			Image:         nodeImage,
			RequiredTools: []string{"bash", "strace", "node", "npm", "pnpm", "curl"},
			SetupCommands: []string{
				"command -v corepack >/dev/null 2>&1 && corepack enable >/dev/null 2>&1 || true",
				"command -v corepack >/dev/null 2>&1 && corepack prepare pnpm@latest --activate >/dev/null 2>&1 || true",
				"command -v pnpm >/dev/null 2>&1 || npm install -g pnpm@latest >/dev/null 2>&1 || true",
			},
		}
	case "bun":
		return scanProfile{
			Name:          "bun",
			Image:         bunImage,
			RequiredTools: []string{"bash", "strace", "bun", "curl"},
		}
	default:
		return scanProfile{
			Name:          "npm",
			Image:         nodeImage,
			RequiredTools: []string{"bash", "strace", "node", "npm", "curl"},
		}
	}
}
