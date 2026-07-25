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
	runtimeCommand  string
	skipStatic      bool
	priorFindings   []report.Finding
	allowNetwork    bool
	runAsRoot       bool
	scanProjectMode bool
	probePackages   []string
	skipProbe       bool
	targetTimeout   string
	probeTimeout    string
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

func networkEnabledForProfile(profileName string, allowNetwork bool) bool {
	if networkMode == "auto" {
		switch profileName {
		case "npm", "pnpm", "bun", "shell":
			return true
		default:
			return false
		}
	}
	if networkMode == "on" {
		return true
	}
	if networkMode == "off" {
		return false
	}
	return allowNetwork
}

// runScanPipeline reports whether the configured verdict policy requires a
// non-zero exit. It never exits itself so callers can release staged project
// trees before terminating the process.
func runScanPipeline(ctx context.Context, targetCmd string, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) (bool, error) {
	runTargetCmd := targetCmd
	if strings.TrimSpace(opts.runtimeCommand) != "" {
		runTargetCmd = opts.runtimeCommand
	}

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
	networkEnabled := networkEnabledForProfile(profile.Name, opts.allowNetwork)

	probeScript := ""
	if len(opts.probePackages) > 0 && !opts.skipProbe && isNodeProfile(profile.Name) {
		probeScript = probe.GenerateNodeProbeScript(opts.probePackages, probeTimeoutSeconds(opts.probeTimeout))
	}
	if opts.targetTimeout == "" {
		opts.targetTimeout = defaultTargetTimeout(profile.Name)
	}
	if opts.probeTimeout == "" {
		opts.probeTimeout = "30s"
	}

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: networkEnabled,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.StopProgress()
		return false, fmt.Errorf("failed to initialize sandbox: %w", err)
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
			profile.Image = defaultImageForProfile(profile.Name)
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
				profile.Image = defaultImageForProfile(profile.Name)
				s.SetImage(profile.Image)
				reporter.UpdateProgress(fmt.Sprintf("Preparing sandbox image %s...", profile.Image))

				// Check runc cache before pulling again.
				if cache != nil && opts.projectPath == "" {
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
						return false, fmt.Errorf("failed to prepare image after runc fallback: %w", err)
					}
				}
			} else {
				reporter.StopProgress()
				return false, fmt.Errorf("failed to prepare image: %w", err)
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
	var traceHealth parser.TraceHealth

	if usedCache {
		dynamicFindings, sandboxRuntime, traceHealth, err = runCachedSandboxAndParse(ctx, s, profile, runTargetCmd, probeScript, opts, registryIPs, reporter)
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
				return false, fmt.Errorf("failed to prepare image: %w", err)
			}
			dynamicFindings, sandboxRuntime, traceHealth, err = runSandboxAndParse(ctx, s, profile, runTargetCmd, probeScript, opts, registryIPs, reporter)
			if err != nil {
				s.Cleanup(ctx, false)
				reporter.StopProgress()
				return false, fmt.Errorf("failed to run command: %w", err)
			}
		}
	} else {
		dynamicFindings, sandboxRuntime, traceHealth, err = runSandboxAndParse(ctx, s, profile, runTargetCmd, probeScript, opts, registryIPs, reporter)
		if err != nil {
			s.Cleanup(ctx, false)
			reporter.StopProgress()
			return false, fmt.Errorf("failed to run command: %w", err)
		}
	}

	fallbackPlan, needsRuncFallback := planRunscDynamicFallback(sandboxRuntime, dynamicFindings, traceHealth)
	if needsRuncFallback {
		s.Cleanup(ctx, false)
		for _, fallbackFinding := range fallbackPlan.Warnings {
			findings = append(findings, fallbackFinding)
			reporter.PrintLiveFinding(fallbackFinding)
		}
		if !ciMode {
			reporter.StopProgress()
			fmt.Print(runscFallbackWarningMessage(fallbackPlan.Reason))
			reporter.StartProgress("Retrying with runc...")
		}

		s.SetRuntime("")
		if isNodeProfile(profile.Name) && profile.Image == sandbox.NodeSandboxImage {
			profile.Image = defaultImageForProfile(profile.Name)
			s.SetImage(profile.Image)
		}

		usedRuncCache := false
		if cache != nil && opts.projectPath == "" {
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
			dynamicFindings, sandboxRuntime, traceHealth, err = runCachedSandboxAndParse(ctx, s, profile, runTargetCmd, probeScript, opts, registryIPs, reporter)
			usedCache = true
		} else {
			if _, err := s.EnsureImage(ctx); err != nil {
				s.Cleanup(ctx, false)
				reporter.StopProgress()
				return false, fmt.Errorf("failed to prepare image after runc fallback: %w", err)
			}
			dynamicFindings, sandboxRuntime, traceHealth, err = runSandboxAndParse(ctx, s, profile, runTargetCmd, probeScript, opts, registryIPs, reporter)
			usedCache = false
		}
		if err != nil {
			s.Cleanup(ctx, false)
			reporter.StopProgress()
			return false, fmt.Errorf("failed to run command after runc fallback: %w", err)
		}
	}

	if !traceHealth.Usable() {
		traceWarning := runtimeTraceUnavailableFinding(traceHealth, sandboxRuntime)
		findings = append(findings, traceWarning)
		reporter.PrintLiveFinding(traceWarning)
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
		Dynamic:                  dynamicMetaFromTraceHealth(traceHealth),
	}
	verdict, _ := reporter.Report(findings, meta)
	return shouldFailOnVerdict(failOn, verdict), nil
}

func shouldFailOnVerdict(policy string, verdict report.Verdict) bool {
	policy = strings.ToLower(strings.TrimSpace(policy))
	switch policy {
	case "", "never", "none", "false", "0":
		return false
	case "malicious":
		return verdict == report.VerdictMalicious
	case "inconclusive":
		return verdict == report.VerdictInconclusive
	case "malicious,inconclusive", "inconclusive,malicious", "all", "true", "1":
		return verdict == report.VerdictMalicious || verdict == report.VerdictInconclusive
	default:
		// Safe default: don't fail closed on unknown config; treat as "never".
		return false
	}
}

func warmSandboxCache(ctx context.Context, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) error {
	if noCache {
		return fmt.Errorf("--warm-cache cannot be used with --no-cache")
	}
	if opts.projectPath != "" {
		return fmt.Errorf("--warm-cache cannot be used for project-staged scans yet")
	}

	networkEnabled := networkEnabledForProfile(profile.Name, opts.allowNetwork)

	reporter.StartProgress("Preparing sandbox cache...")

	cache, err := sandbox.NewCacheManager(cacheDir)
	if err != nil {
		reporter.StopProgress()
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cache.Close()

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: networkEnabled,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.StopProgress()
		return fmt.Errorf("failed to initialize sandbox: %w", err)
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
				profile.Image = defaultImageForProfile(profile.Name)
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
			return nil
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
			profile.Image = defaultImageForProfile(profile.Name)
			s.SetImage(profile.Image)
			if cached := cache.Lookup(ctx, "", profile.Name, opts.runAsRoot, networkEnabled); cached != nil && cached.Image == profile.Image && !cache.ImageChanged(ctx, cached.Image, cached.ImageDigest) {
				reporter.StopProgress()
				if !ciMode {
					fmt.Printf("Sandbox cache is already warm for %s (runc).\n", profile.Name)
				}
				return nil
			}
			if _, err := s.EnsureImage(ctx); err != nil {
				reporter.StopProgress()
				return fmt.Errorf("failed to prepare image after runc fallback: %w", err)
			}
		} else {
			reporter.StopProgress()
			return fmt.Errorf("failed to prepare image: %w", err)
		}
	}

	reporter.UpdateProgress("Warming sandbox cache...")
	if err := s.PrepareWarm(ctx, profile.Name, s.Image(), profile.RequiredTools, profile.SetupCommands); err != nil {
		s.Cleanup(ctx, false)
		reporter.StopProgress()
		return fmt.Errorf("failed to warm cache: %w", err)
	}
	digest, digestErr := s.InspectImageDigest(ctx, s.Image())
	if digestErr != nil {
		digest = cache.LocalImageDigest(ctx, s.Image())
	}
	if err := cache.Store(ctx, s.Runtime(), profile.Name, opts.runAsRoot, networkEnabled, s.ContainerID(), s.Image(), digest); err != nil {
		s.Cleanup(ctx, false)
		reporter.StopProgress()
		return fmt.Errorf("failed to save cache: %w", err)
	}

	reporter.StopProgress()
	if !ciMode {
		rt := s.Runtime()
		if rt == "" {
			rt = "runc"
		}
		fmt.Printf("Warmed sandbox cache for %s (%s).\n", profile.Name, rt)
	}
	return nil
}

func runSandboxAndParse(
	ctx context.Context,
	s *sandbox.Sandbox,
	profile scanProfile,
	targetCmd string,
	probeScript string,
	opts pipelineOptions,
	registryIPs map[string]string,
	reporter *report.Reporter,
) ([]report.Finding, string, parser.TraceHealth, error) {
	if len(opts.probePackages) > 0 && !opts.skipProbe {
		reporter.UpdateProgress(fmt.Sprintf("Running in sandbox + probing %d package(s)...", len(opts.probePackages)))
	}

	var logStream io.Reader
	var err error
	if opts.projectPath != "" {
		logStream, err = s.RunProjectCommand(ctx, targetCmd, probeScript, opts.projectPath, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands, opts.targetTimeout, opts.probeTimeout)
	} else {
		logStream, err = s.RunCommand(ctx, targetCmd, probeScript, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands, opts.targetTimeout, opts.probeTimeout)
	}
	if err != nil {
		return nil, "", parser.TraceHealth{}, err
	}

	dynamicFindings, traceHealth, err := parser.ParseStreamWithHealth(logStream, reporter, parser.ParseOptions{
		KnownRegistryIPs: registryIPs,
		ProbeExpected:    len(opts.probePackages) > 0 && !opts.skipProbe,
	})
	if err != nil {
		return nil, "", traceHealth, err
	}

	runtime := s.Runtime()
	if runtime == "" {
		runtime = "runc"
	}
	return dynamicFindings, runtime, traceHealth, nil
}

// runCachedSandboxAndParse runs a scan on a cached (warm) container via ExecScan.
func runCachedSandboxAndParse(
	ctx context.Context,
	s *sandbox.Sandbox,
	profile scanProfile,
	targetCmd string,
	probeScript string,
	opts pipelineOptions,
	registryIPs map[string]string,
	reporter *report.Reporter,
) ([]report.Finding, string, parser.TraceHealth, error) {
	if len(opts.probePackages) > 0 && !opts.skipProbe {
		reporter.UpdateProgress(fmt.Sprintf("Running in cached sandbox + probing %d package(s)...", len(opts.probePackages)))
	}

	logStream, err := s.ExecScan(ctx, targetCmd, probeScript, profile.Name, profile.Image, opts.projectPath, opts.targetTimeout, opts.probeTimeout)
	if err != nil {
		return nil, "", parser.TraceHealth{}, err
	}

	dynamicFindings, traceHealth, err := parser.ParseStreamWithHealth(logStream, reporter, parser.ParseOptions{
		KnownRegistryIPs: registryIPs,
		ProbeExpected:    len(opts.probePackages) > 0 && !opts.skipProbe,
	})
	if err != nil {
		return nil, "", traceHealth, err
	}

	runtime := s.Runtime()
	if runtime == "" {
		runtime = "runc"
	}
	return dynamicFindings, runtime, traceHealth, nil
}

func runtimeTraceUnavailableFinding(health parser.TraceHealth, runtime string) report.Finding {
	if runtime == "" {
		runtime = "runc"
	}
	return report.Finding{
		Severity:   report.SeverityWarning,
		Type:       "runtime",
		ReasonCode: "RUNTIME_TRACE_UNAVAILABLE",
		Path:       "sandbox",
		Confidence: 90,
		Evidence:   fmt.Sprintf("%s runtime trace incomplete: %s", runtime, strings.Join(traceHealthMissingReasons(health), ", ")),
	}
}

func runscTraceFallbackFinding(health parser.TraceHealth) report.Finding {
	return report.Finding{
		Severity:   report.SeverityWarning,
		Type:       "runtime",
		ReasonCode: "RUNSC_TRACE_FALLBACK_RUNC",
		Path:       "sandbox",
		Confidence: 85,
		Evidence:   fmt.Sprintf("gVisor runtime trace unavailable; retried scan using runc: %s", strings.Join(traceHealthMissingReasons(health), ", ")),
	}
}

type runscDynamicFallbackPlan struct {
	Reason   string
	Warnings []report.Finding
}

func planRunscDynamicFallback(runtime string, dynamicFindings []report.Finding, traceHealth parser.TraceHealth) (runscDynamicFallbackPlan, bool) {
	if runtime != "runsc" {
		return runscDynamicFallbackPlan{}, false
	}
	if parser.HasPrepFailure(dynamicFindings) {
		return runscDynamicFallbackPlan{
			Reason: "prep_failed",
			Warnings: []report.Finding{{
				Severity:   report.SeverityWarning,
				Type:       "runtime",
				ReasonCode: "RUNSC_FALLBACK_RUNC",
				Path:       "sandbox",
				Confidence: 85,
				Evidence:   "gVisor prep failed; retried scan using runc",
			}},
		}, true
	}
	if !traceHealth.Usable() {
		return runscDynamicFallbackPlan{
			Reason: "trace_unavailable",
			Warnings: []report.Finding{
				runtimeTraceUnavailableFinding(traceHealth, "runsc"),
				runscTraceFallbackFinding(traceHealth),
			},
		}, true
	}
	return runscDynamicFallbackPlan{}, false
}

func runscFallbackWarningMessage(reason string) string {
	if reason == "prep_failed" {
		return "\033[33m[WARNING] gVisor sandbox prep failed (tools/apt). Retrying with runc; npm install behavior is still scanned.\033[0m\r\n"
	}
	return "\033[33m[WARNING] gVisor runtime tracing was unavailable. Retrying with runc; weaker isolation will be noted in the report.\033[0m\r\n"
}

func traceHealthMissingReasons(health parser.TraceHealth) []string {
	var reasons []string
	if !health.TargetPhaseObserved {
		reasons = append(reasons, "missing target phase marker")
	}
	if !health.TargetExitObserved {
		reasons = append(reasons, "missing target exit marker")
	}
	if !health.TargetSyscallObserved {
		reasons = append(reasons, "missing target syscall evidence")
	}
	if health.ProbeExpected && !health.ProbePhaseObserved {
		reasons = append(reasons, "missing probe phase marker")
	}
	if health.ProbeExpected && !health.ProbeExitObserved {
		reasons = append(reasons, "missing probe exit marker")
	}
	if health.ProbeExpected && !health.ProbeSyscallObserved {
		reasons = append(reasons, "missing probe syscall evidence")
	}
	if health.ProbeExpected && health.ProbeExitObserved && health.ProbeExitCode != 0 {
		reasons = append(reasons, fmt.Sprintf("probe exited with status %d", health.ProbeExitCode))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "unknown trace health failure")
	}
	return reasons
}

func dynamicMetaFromTraceHealth(health parser.TraceHealth) *report.DynamicMeta {
	return &report.DynamicMeta{
		Target: report.DynamicPhaseMeta{
			Expected:        true,
			PhaseObserved:   health.TargetPhaseObserved,
			ExitObserved:    health.TargetExitObserved,
			ExitCode:        health.TargetExitCode,
			SyscallObserved: health.TargetSyscallObserved,
			TimedOut:        health.TargetExitObserved && health.TargetExitCode == 124,
		},
		Probe: report.DynamicPhaseMeta{
			Expected:        health.ProbeExpected,
			PhaseObserved:   health.ProbePhaseObserved,
			ExitObserved:    health.ProbeExitObserved,
			ExitCode:        health.ProbeExitCode,
			SyscallObserved: health.ProbeSyscallObserved,
			TimedOut:        health.ProbeExitObserved && health.ProbeExitCode == 124,
		},
	}
}

func isNodeProfile(name string) bool {
	switch name {
	case "npm", "pnpm", "bun":
		return true
	}
	return false
}

func shouldUsePublishedNodeSandbox(runtime string, profile scanProfile) bool {
	if runtime != "runsc" || !isNodeProfile(profile.Name) {
		return false
	}
	return profile.Image == sandbox.DefaultNodeImage || profile.Image == sandbox.DefaultBunImage
}

// defaultImageForProfile returns the stock runc fallback image for the given profile.
func defaultImageForProfile(profileName string) string {
	if profileName == "bun" {
		return sandbox.DefaultBunImage
	}
	return sandbox.DefaultNodeImage
}

func defaultTargetTimeout(profileName string) string {
	switch profileName {
	case "npm", "pnpm", "bun":
		return "180s"
	case "shell":
		return "120s"
	default:
		return "120s"
	}
}

func probeTimeoutSeconds(timeoutValue string) int {
	if strings.HasSuffix(timeoutValue, "s") {
		var seconds int
		if _, err := fmt.Sscanf(timeoutValue, "%ds", &seconds); err == nil && seconds > 0 {
			return seconds
		}
	}
	return probe.DefaultTimeoutSec * 2
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
