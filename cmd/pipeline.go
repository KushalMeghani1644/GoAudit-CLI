package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/analyzer"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/parser"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/probe"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/sandbox"
)

type pipelineOptions struct {
	projectPath     string
	skipStatic      bool
	priorFindings   []report.Finding
	allowNetwork    bool
	runAsRoot       bool
	scanProjectMode bool
	probePackages   []string
	skipProbe       bool
}

// resolveRegistryIPs resolves known registry hostnames to IPs for classification.
func resolveRegistryIPs(profileName string) map[string]string {
	registries := []string{"registry.npmjs.org"}
	switch profileName {
	case "pnpm":
		registries = append(registries, "registry.npmmirror.com")
	}
	result := map[string]string{}
	for _, host := range registries {
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			result[ip] = host
		}
	}
	return result
}

func runScanPipeline(ctx context.Context, targetCmd string, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) {
	findings := append([]report.Finding{}, opts.priorFindings...)

	reporter.StartProgress("Running static analysis...")

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
				Severity: report.SeverityWarning, Type: "policy", ReasonCode: "INCONCLUSIVE_REMOTE_FETCH",
				Path: strings.Join(urls, ","), Confidence: 35, Evidence: "Offline mode disabled remote script retrieval",
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

	// Determine network policy
	networkEnabled := opts.allowNetwork
	if networkMode == "auto" {
		switch profile.Name {
		case "npm", "pnpm", "bun":
			networkEnabled = true
		default:
			networkEnabled = false
		}
	} else if networkMode == "on" {
		networkEnabled = true
	} else if networkMode == "off" {
		networkEnabled = false
	}

	// Append runtime probe
	finalCmd := targetCmd
	if len(opts.probePackages) > 0 && !opts.skipProbe && isNodeProfile(profile.Name) {
		probeScript := probe.GenerateNodeProbeScript(opts.probePackages, probe.DefaultTimeoutSec)
		finalCmd = targetCmd + "\n" + probeScript
	}

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: networkEnabled,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.StopProgress()
		reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
	}

	if shouldUsePublishedNodeSandbox(s.Runtime(), profile) {
		profile.Image = sandbox.NodeSandboxImage
		s.SetImage(profile.Image)
	}

	reporter.UpdateProgress(fmt.Sprintf("Preparing sandbox image %s...", profile.Image))

	// --- Cache integration ---
	var cache *sandbox.CacheManager
	usedCache := false
	forcedRuncOffline := false
	if !noCache {
		cache, err = sandbox.NewCacheManager(cacheDir)
		if err != nil && !ciMode {
			fmt.Printf("\033[33m[WARNING] Could not initialize cache: %v. Running without cache.\033[0m\r\n", err)
		}
	}
	if cache != nil {
		defer cache.Close()
	}

	// Try to use cached sandbox if available.
	if cache != nil && opts.projectPath == "" {
		cached := cache.Lookup(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled)
		if cached != nil {
			if cached.Image != profile.Image {
				cache.Invalidate(ctx, cached.Runtime, profile.Name, cached.RunAsRoot, cached.Network)
				cached = nil
			}
		}
		if cached != nil {
			refresh, offline := cache.ShouldRefreshLatest(ctx, cached)
			if refresh {
				if offline && cached.Runtime == "runsc" && isNodeProfile(profile.Name) {
					forcedRuncOffline = true
				}
				cache.Invalidate(ctx, cached.Runtime, profile.Name, cached.RunAsRoot, cached.Network)
				cached = nil
			}
		}
		if cached != nil {
			if !cache.ImageChanged(ctx, cached.Image, cached.ImageDigest) {
				reporter.UpdateProgress("Using cached sandbox...")
				s.SetContainerID(cached.ContainerID)
				s.SetImage(cached.Image)
				if cached.Runtime == "runsc" {
					s.SetRuntime("runsc")
				} else {
					s.SetRuntime("")
				}
				cache.TouchLastUsed(cached.Runtime, profile.Name, cached.RunAsRoot, cached.Network)
				usedCache = true
				// Update profile image to match the cached one.
				profile.Image = cached.Image
			} else {
				// Image changed, invalidate old cache.
				cache.Invalidate(ctx, cached.Runtime, profile.Name, cached.RunAsRoot, cached.Network)
			}
		}
	}

	imageFallbackToRunc := false

	if !usedCache {
		if forcedRuncOffline && s.Runtime() == "runsc" && isNodeProfile(profile.Name) && profile.Image == sandbox.NodeSandboxImage {
			imageFallbackToRunc = true
			fallback := report.Finding{
				Severity:   report.SeverityWarning,
				Type:       "runtime",
				ReasonCode: "RUNSC_FALLBACK_RUNC",
				Path:       "sandbox",
				Confidence: 85,
				Evidence:   "No internet available, falling back to runc",
			}
			findings = append(findings, fallback)
			reporter.PrintLiveFinding(fallback)
			if !ciMode {
				reporter.StopProgress()
				fmt.Printf("\033[33m[WARNING] No internet available, falling back to runc.\033[0m\r\n")
				reporter.StartProgress("Retrying with runc...")
			}
			s.SetRuntime("")
			profile.Image = sandbox.DefaultNodeImage
			s.SetImage(profile.Image)
		}
		if _, err := s.EnsureImage(ctx); err != nil {
			if s.Runtime() == "runsc" && isNodeProfile(profile.Name) && profile.Image == sandbox.NodeSandboxImage {
				imageFallbackToRunc = true
				fallback := report.Finding{
					Severity:   report.SeverityWarning,
					Type:       "runtime",
					ReasonCode: "RUNSC_FALLBACK_RUNC",
					Path:       "sandbox",
					Confidence: 85,
					Evidence:   fmt.Sprintf("could not prepare gVisor sandbox image %s; no internet available, falling back to runc: %v", sandbox.NodeSandboxImage, err),
				}
				findings = append(findings, fallback)
				reporter.PrintLiveFinding(fallback)
				if !ciMode {
					reporter.StopProgress()
					fmt.Printf("\033[33m[WARNING] Could not prepare gVisor sandbox image %s. No internet available, falling back to runc.\033[0m\r\n", sandbox.NodeSandboxImage)
					reporter.StartProgress("Retrying with runc...")
				}
				s.SetRuntime("")
				profile.Image = sandbox.DefaultNodeImage
				s.SetImage(profile.Image)
				reporter.UpdateProgress(fmt.Sprintf("Preparing sandbox image %s...", profile.Image))

				// Check runc cache before pulling again.
				if cache != nil {
					runcCached := cache.Lookup(ctx, "", profile.Name, opts.runAsRoot, networkEnabled)
					if runcCached != nil && runcCached.Image == profile.Image && !cache.ImageChanged(ctx, runcCached.Image, runcCached.ImageDigest) {
						reporter.UpdateProgress("Using cached runc sandbox...")
						s.SetContainerID(runcCached.ContainerID)
						s.SetImage(runcCached.Image)
						profile.Image = runcCached.Image
						cache.TouchLastUsed("", profile.Name, runcCached.RunAsRoot, runcCached.Network)
						usedCache = true
					}
				}

				if !usedCache {
					if _, err := s.EnsureImage(ctx); err != nil {
						reporter.StopProgress()
						reporter.Fatalf("Failed to prepare image after runc fallback: %v\n", err)
					}
				}
			} else {
				reporter.StopProgress()
				reporter.Fatalf("Failed to prepare image: %v\n", err)
			}
		}
	}

	if s.Runtime() != "runsc" && !ciMode && !imageFallbackToRunc {
		reporter.StopProgress()
		fmt.Print("\033[33m[WARNING] gVisor (runsc) is not registered in Docker (see docker info Runtimes). Using default runtime (runc).\033[0m\r\n")
		reporter.StartProgress("Running in sandbox...")
	}

	reporter.UpdateProgress(fmt.Sprintf("Running %s in sandbox...", profile.Name))

	registryIPs := resolveRegistryIPs(profile.Name)

	// If using cached sandbox, warm-start via ExecScan; otherwise do the normal cold path.
	var dynamicFindings []report.Finding
	var sandboxRuntime string

	if usedCache {
		dynamicFindings, sandboxRuntime, err = runCachedSandboxAndParse(ctx, s, profile, finalCmd, opts, registryIPs, reporter)
		if err != nil {
			// Cache might be stale; invalidate and fall through to cold path.
			if cache != nil {
				cache.Invalidate(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled)
			}
			s.Cleanup(ctx, false)
			if !ciMode {
				reporter.StopProgress()
				fmt.Print("\033[33m[WARNING] Cached sandbox failed. Creating fresh sandbox.\033[0m\r\n")
				reporter.StartProgress("Running in fresh sandbox...")
			}
			usedCache = false
			// Pull image and do a cold run.
			if _, err := s.EnsureImage(ctx); err != nil {
				reporter.StopProgress()
				reporter.Fatalf("Failed to prepare image: %v\n", err)
			}
			dynamicFindings, sandboxRuntime, err = runSandboxAndParse(ctx, s, profile, finalCmd, opts, registryIPs, reporter)
			if err != nil {
				s.Cleanup(ctx, false)
				reporter.StopProgress()
				reporter.Fatalf("Failed to run command: %v\n", err)
			}
		}
	} else {
		dynamicFindings, sandboxRuntime, err = runSandboxAndParse(ctx, s, profile, finalCmd, opts, registryIPs, reporter)
		if err != nil {
			s.Cleanup(ctx, false)
			reporter.StopProgress()
			reporter.Fatalf("Failed to run command: %v\n", err)
		}
	}

	// If gVisor prep failed (often apt-get under runsc), retry once with runc.
	if s.Runtime() == "runsc" && parser.HasPrepFailure(dynamicFindings) {
		s.Cleanup(ctx, false)
		if !ciMode {
			reporter.StopProgress()
			fmt.Print("\033[33m[WARNING] gVisor sandbox prep failed (tools/apt). Retrying with runc; npm install behavior is still scanned.\033[0m\r\n")
			reporter.StartProgress("Retrying with runc...")
		}
		fallback := report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "runtime",
			ReasonCode: "RUNSC_FALLBACK_RUNC",
			Path:       "sandbox",
			Confidence: 85,
			Evidence:   "gVisor prep failed; retried scan using runc",
		}
		findings = append(findings, fallback)
		reporter.PrintLiveFinding(fallback)

		s.SetRuntime("")
		if isNodeProfile(profile.Name) && profile.Image == sandbox.NodeSandboxImage {
			profile.Image = sandbox.DefaultNodeImage
			s.SetImage(profile.Image)
		}

		usedRuncCache := false
		if cache != nil {
			runcCached := cache.Lookup(ctx, "", profile.Name, opts.runAsRoot, networkEnabled)
			if runcCached != nil && runcCached.Image == profile.Image && !cache.ImageChanged(ctx, runcCached.Image, runcCached.ImageDigest) {
				reporter.UpdateProgress("Using cached runc sandbox...")
				s.SetContainerID(runcCached.ContainerID)
				s.SetImage(runcCached.Image)
				profile.Image = runcCached.Image
				cache.TouchLastUsed("", profile.Name, opts.runAsRoot, networkEnabled)
				usedRuncCache = true
			}
		}
		if usedRuncCache {
			dynamicFindings, sandboxRuntime, err = runCachedSandboxAndParse(ctx, s, profile, finalCmd, opts, registryIPs, reporter)
			usedCache = true
		} else {
			if _, err := s.EnsureImage(ctx); err != nil {
				s.Cleanup(ctx, false)
				reporter.StopProgress()
				reporter.Fatalf("Failed to prepare image after runc fallback: %v\n", err)
			}
			dynamicFindings, sandboxRuntime, err = runSandboxAndParse(ctx, s, profile, finalCmd, opts, registryIPs, reporter)
		}
		if err != nil {
			s.Cleanup(ctx, false)
			reporter.StopProgress()
			reporter.Fatalf("Failed to run command after runc fallback: %v\n", err)
		}
	}

	findings = append(findings, dynamicFindings...)

	// Cache the warm container for next time (if caching is enabled and we did a cold run).
	if cache != nil && !noCache && !usedCache && opts.projectPath == "" {
		// Warm-prepare a fresh container for the cache.
		reporter.UpdateProgress("Warming sandbox cache...")
		warmSandbox, warmErr := sandbox.NewSandbox(ctx, s.Image(), sandbox.SandboxOptions{
			RunAsRoot: opts.runAsRoot,
		})
		if warmErr == nil {
			warmSandbox.SetRuntime(s.Runtime())
			warmSandbox.SetImage(s.Image())
			if warmErr = warmSandbox.PrepareWarm(ctx, profile.Name, s.Image(), profile.RequiredTools, profile.SetupCommands); warmErr == nil {
				digest, digestErr := warmSandbox.InspectImageDigest(ctx, s.Image())
				if digestErr != nil {
					digest = cache.LocalImageDigest(ctx, s.Image())
				}
				if storeErr := cache.Store(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled, warmSandbox.ContainerID(), s.Image(), digest); storeErr != nil && !ciMode {
					fmt.Printf("\033[33m[WARNING] Could not save cache: %v\033[0m\r\n", storeErr)
				}
			} else {
				warmSandbox.Cleanup(ctx, false)
				if !ciMode {
					fmt.Printf("\033[33m[WARNING] Could not warm cache: %v\033[0m\r\n", warmErr)
				}
			}
		}
	}

	// Cleanup the scan container (not the cached warm container).
	s.Cleanup(ctx, usedCache)

	if sandboxRuntime == "" {
		sandboxRuntime = "runc"
	}

	meta := report.ReportMeta{
		Command:                  targetCmd,
		ProfileName:              profile.Name,
		SandboxRuntime:           sandboxRuntime,
		SuppressExpectedBehavior: isNodeProfile(profile.Name),
	}
	reporter.Report(findings, meta)
}

func warmSandboxCache(ctx context.Context, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) {
	if noCache {
		reporter.Fatalf("--warm-cache cannot be used with --no-cache\n")
	}
	if opts.projectPath != "" {
		reporter.Fatalf("--warm-cache cannot be used for project-mounted scans yet\n")
	}

	networkEnabled := opts.allowNetwork
	if networkMode == "auto" {
		switch profile.Name {
		case "npm", "pnpm", "bun":
			networkEnabled = true
		default:
			networkEnabled = false
		}
	} else if networkMode == "on" {
		networkEnabled = true
	} else if networkMode == "off" {
		networkEnabled = false
	}

	reporter.StartProgress("Preparing sandbox cache...")

	cache, err := sandbox.NewCacheManager(cacheDir)
	if err != nil {
		reporter.StopProgress()
		reporter.Fatalf("Failed to initialize cache: %v\n", err)
	}
	defer cache.Close()

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: true,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.StopProgress()
		reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
	}

	if shouldUsePublishedNodeSandbox(s.Runtime(), profile) {
		profile.Image = sandbox.NodeSandboxImage
		s.SetImage(profile.Image)
	}

	if cached := cache.Lookup(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled); cached != nil {
		refresh, offline := cache.ShouldRefreshLatest(ctx, cached)
		if refresh {
			cache.Invalidate(ctx, cached.Runtime, profile.Name, cached.RunAsRoot, cached.Network)
			cached = nil
			if offline && s.Runtime() == "runsc" && isNodeProfile(profile.Name) {
				if !ciMode {
					reporter.StopProgress()
					fmt.Printf("\033[33m[WARNING] No internet available, falling back to runc.\033[0m\r\n")
					reporter.StartProgress("Preparing runc sandbox cache...")
				}
				s.SetRuntime("")
				profile.Image = sandbox.DefaultNodeImage
				s.SetImage(profile.Image)
			}
		}
		if cached != nil && cached.Image == profile.Image && !cache.ImageChanged(ctx, cached.Image, cached.ImageDigest) {
			reporter.StopProgress()
			if !ciMode {
				rt := cached.Runtime
				if rt == "" {
					rt = "runc"
				}
				fmt.Printf("Sandbox cache is already warm for %s (%s).\n", profile.Name, rt)
			}
			return
		}
	}

	reporter.UpdateProgress(fmt.Sprintf("Preparing sandbox image %s...", profile.Image))
	if _, err := s.EnsureImage(ctx); err != nil {
		if s.Runtime() == "runsc" && isNodeProfile(profile.Name) && profile.Image == sandbox.NodeSandboxImage {
			if !ciMode {
				reporter.StopProgress()
				fmt.Printf("\033[33m[WARNING] Could not prepare gVisor sandbox image %s. No internet available, falling back to runc.\033[0m\r\n", sandbox.NodeSandboxImage)
				reporter.StartProgress("Preparing runc sandbox cache...")
			}
			s.SetRuntime("")
			profile.Image = sandbox.DefaultNodeImage
			s.SetImage(profile.Image)
			if cached := cache.Lookup(ctx, "", profile.Name, opts.runAsRoot, networkEnabled); cached != nil && cached.Image == profile.Image && !cache.ImageChanged(ctx, cached.Image, cached.ImageDigest) {
				reporter.StopProgress()
				if !ciMode {
					fmt.Printf("Sandbox cache is already warm for %s (runc).\n", profile.Name)
				}
				return
			}
			if _, err := s.EnsureImage(ctx); err != nil {
				reporter.StopProgress()
				reporter.Fatalf("Failed to prepare image after runc fallback: %v\n", err)
			}
		} else {
			reporter.StopProgress()
			reporter.Fatalf("Failed to prepare image: %v\n", err)
		}
	}

	reporter.UpdateProgress("Warming sandbox cache...")
	if err := s.PrepareWarm(ctx, profile.Name, s.Image(), profile.RequiredTools, profile.SetupCommands); err != nil {
		s.Cleanup(ctx, false)
		reporter.StopProgress()
		reporter.Fatalf("Failed to warm cache: %v\n", err)
	}
	digest, digestErr := s.InspectImageDigest(ctx, s.Image())
	if digestErr != nil {
		digest = cache.LocalImageDigest(ctx, s.Image())
	}
	if err := cache.Store(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled, s.ContainerID(), s.Image(), digest); err != nil {
		s.Cleanup(ctx, false)
		reporter.StopProgress()
		reporter.Fatalf("Failed to save cache: %v\n", err)
	}

	reporter.StopProgress()
	if !ciMode {
		rt := s.Runtime()
		if rt == "" {
			rt = "runc"
		}
		fmt.Printf("Warmed sandbox cache for %s (%s).\n", profile.Name, rt)
	}
}

func runSandboxAndParse(
	ctx context.Context,
	s *sandbox.Sandbox,
	profile scanProfile,
	finalCmd string,
	opts pipelineOptions,
	registryIPs map[string]string,
	reporter *report.Reporter,
) ([]report.Finding, string, error) {
	if len(opts.probePackages) > 0 && !opts.skipProbe {
		reporter.UpdateProgress(fmt.Sprintf("Running in sandbox + probing %d package(s)...", len(opts.probePackages)))
	}

	var logStream io.Reader
	var err error
	if opts.projectPath != "" {
		logStream, err = s.RunProjectCommand(ctx, finalCmd, opts.projectPath, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	} else {
		logStream, err = s.RunCommand(ctx, finalCmd, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	}
	if err != nil {
		return nil, "", err
	}

	dynamicFindings, err := parser.ParseStream(logStream, reporter, parser.ParseOptions{
		KnownRegistryIPs: registryIPs,
	})
	if err != nil {
		return nil, "", err
	}

	runtime := s.Runtime()
	if runtime == "" {
		runtime = "runc"
	}
	return dynamicFindings, runtime, nil
}

// runCachedSandboxAndParse runs a scan on a cached (warm) container via ExecScan.
func runCachedSandboxAndParse(
	ctx context.Context,
	s *sandbox.Sandbox,
	profile scanProfile,
	finalCmd string,
	opts pipelineOptions,
	registryIPs map[string]string,
	reporter *report.Reporter,
) ([]report.Finding, string, error) {
	if len(opts.probePackages) > 0 && !opts.skipProbe {
		reporter.UpdateProgress(fmt.Sprintf("Running in cached sandbox + probing %d package(s)...", len(opts.probePackages)))
	}

	logStream, err := s.ExecScan(ctx, finalCmd, profile.Name, profile.Image, opts.projectPath)
	if err != nil {
		return nil, "", err
	}

	dynamicFindings, err := parser.ParseStream(logStream, reporter, parser.ParseOptions{
		KnownRegistryIPs: registryIPs,
	})
	if err != nil {
		return nil, "", err
	}

	runtime := s.Runtime()
	if runtime == "" {
		runtime = "runc"
	}
	return dynamicFindings, runtime, nil
}

func isNodeProfile(name string) bool {
	switch name {
	case "npm", "pnpm", "bun":
		return true
	}
	return false
}

func shouldUsePublishedNodeSandbox(runtime string, profile scanProfile) bool {
	return runtime == "runsc" && isNodeProfile(profile.Name) && profile.Image == sandbox.DefaultNodeImage
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
