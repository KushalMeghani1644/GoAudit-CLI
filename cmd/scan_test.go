package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/parser"
	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func TestInferProfileForPackageManagers(t *testing.T) {
	nodeImage = "node:current-slim"
	bunImage = "oven/bun:1"

	npm := inferProfile("npm install lodash")
	if npm.Name != "npm" || npm.Image != nodeImage {
		t.Fatalf("unexpected npm profile: %#v", npm)
	}

	pnpm := inferProfile("pnpm add lodash")
	if pnpm.Name != "pnpm" || pnpm.Image != nodeImage {
		t.Fatalf("unexpected pnpm profile: %#v", pnpm)
	}
	if len(pnpm.SetupCommands) == 0 {
		t.Fatalf("expected pnpm setup commands")
	}

	bun := inferProfile("bun add lodash")
	if bun.Name != "bun" || bun.Image != bunImage {
		t.Fatalf("unexpected bun profile: %#v", bun)
	}
}

func TestShouldUsePublishedNodeSandbox(t *testing.T) {
	if !shouldUsePublishedNodeSandbox("runsc", scanProfile{Name: "npm", Image: "node:current-slim"}) {
		t.Fatal("expected default npm runsc scan to use published sandbox image")
	}
	if shouldUsePublishedNodeSandbox("runsc", scanProfile{Name: "npm", Image: "custom/node:latest"}) {
		t.Fatal("expected custom node image to be preserved")
	}
	if shouldUsePublishedNodeSandbox("", scanProfile{Name: "npm", Image: "node:current-slim"}) {
		t.Fatal("expected runc scan to keep stock node image")
	}
	if shouldUsePublishedNodeSandbox("runsc", scanProfile{Name: "python", Image: "node:current-slim"}) {
		t.Fatal("expected non-node profile to keep its image")
	}
}

func TestNetworkAutoEnablesShellScans(t *testing.T) {
	old := networkMode
	networkMode = "auto"
	defer func() { networkMode = old }()
	if !networkEnabledForProfile("shell", false) {
		t.Fatal("expected shell scans to enable network in auto mode")
	}
	if networkEnabledForProfile("python", false) {
		t.Fatal("did not expect python scans to enable network in auto mode")
	}
}

func TestDefaultTargetTimeouts(t *testing.T) {
	if got := defaultTargetTimeout("npm"); got != "180s" {
		t.Fatalf("unexpected npm timeout: %s", got)
	}
	if got := defaultTargetTimeout("shell"); got != "120s" {
		t.Fatalf("unexpected shell timeout: %s", got)
	}
}

func TestPrepareLocalPackageInstallRewritesSingleLocalPackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"local-pkg"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	runtimeCmd, projectPath, findings := prepareLocalPackageInstall("npm install " + dir)
	if runtimeCmd != "npm install ." {
		t.Fatalf("unexpected runtime command: %s", runtimeCmd)
	}
	if projectPath != dir {
		t.Fatalf("unexpected project path: %s", projectPath)
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestPrepareLocalPackageInstallRefusesMultiLocalWithoutMountCwd(t *testing.T) {
	prev := mountCwd
	mountCwd = false
	defer func() { mountCwd = prev }()

	runtimeCmd, projectPath, findings := prepareLocalPackageInstall("npm install ./one ./two")
	if runtimeCmd != "npm install ./one ./two" {
		t.Fatalf("unexpected runtime command: %s", runtimeCmd)
	}
	if projectPath != "" {
		t.Fatalf("expected empty project path without --mount-cwd, got %q", projectPath)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one warning, got %#v", findings)
	}
	if findings[0].ReasonCode != "LOCAL_PACKAGE_REWRITE_UNAVAILABLE" {
		t.Fatalf("unexpected reason: %s", findings[0].ReasonCode)
	}
	if !strings.Contains(findings[0].Evidence, "--mount-cwd") {
		t.Fatalf("unexpected evidence: %s", findings[0].Evidence)
	}
}

func TestPrepareLocalPackageInstallMountCwdFallback(t *testing.T) {
	prev := mountCwd
	mountCwd = true
	defer func() { mountCwd = prev }()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	runtimeCmd, projectPath, findings := prepareLocalPackageInstall("npm install ./one ./two")
	if runtimeCmd != "npm install ./one ./two" {
		t.Fatalf("unexpected runtime command: %s", runtimeCmd)
	}
	if projectPath != wd {
		t.Fatalf("unexpected project path: %s", projectPath)
	}
	if len(findings) < 1 {
		t.Fatalf("expected warnings, got %#v", findings)
	}
	foundRewrite := false
	foundMount := false
	for _, f := range findings {
		if f.ReasonCode == "LOCAL_PACKAGE_REWRITE_UNAVAILABLE" {
			foundRewrite = true
		}
		if f.ReasonCode == "PROJECT_TREE_MOUNTED" {
			foundMount = true
		}
	}
	if !foundRewrite || !foundMount {
		t.Fatalf("expected rewrite + mount warnings, got %#v", findings)
	}
}

func TestRuntimeTraceUnavailableFindingIncludesMissingReasons(t *testing.T) {
	f := runtimeTraceUnavailableFinding(parser.TraceHealth{
		ProbeExpected: true,
	}, "runsc")
	if f.ReasonCode != "RUNTIME_TRACE_UNAVAILABLE" {
		t.Fatalf("unexpected reason: %s", f.ReasonCode)
	}
	for _, want := range []string{"runsc", "missing target phase marker", "missing target exit marker", "missing target syscall evidence", "missing probe phase marker"} {
		if !strings.Contains(f.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got %q", want, f.Evidence)
		}
	}
}

func TestRunscTraceFallbackFinding(t *testing.T) {
	f := runscTraceFallbackFinding(parser.TraceHealth{})
	if f.ReasonCode != "RUNSC_TRACE_FALLBACK_RUNC" {
		t.Fatalf("unexpected reason: %s", f.ReasonCode)
	}
	if !strings.Contains(f.Evidence, "retried scan using runc") {
		t.Fatalf("expected runc fallback evidence, got %q", f.Evidence)
	}
}

func TestPlanRunscDynamicFallbackPrepFailure(t *testing.T) {
	plan, ok := planRunscDynamicFallback("runsc", []report.Finding{{ReasonCode: "RUNTIME_PREP_FAILURE"}}, parser.TraceHealth{})
	if !ok {
		t.Fatal("expected fallback plan for prep failure")
	}
	if plan.Reason != "prep_failed" {
		t.Fatalf("unexpected plan reason: %s", plan.Reason)
	}
	if len(plan.Warnings) != 1 || plan.Warnings[0].ReasonCode != "RUNSC_FALLBACK_RUNC" {
		t.Fatalf("unexpected warnings: %#v", plan.Warnings)
	}
}

func TestPlanRunscDynamicFallbackTraceUnavailable(t *testing.T) {
	plan, ok := planRunscDynamicFallback("runsc", nil, parser.TraceHealth{})
	if !ok {
		t.Fatal("expected fallback plan for unusable trace")
	}
	if plan.Reason != "trace_unavailable" {
		t.Fatalf("unexpected plan reason: %s", plan.Reason)
	}
	if len(plan.Warnings) != 2 {
		t.Fatalf("expected two warnings for trace fallback, got %d", len(plan.Warnings))
	}
	if plan.Warnings[0].ReasonCode != "RUNTIME_TRACE_UNAVAILABLE" {
		t.Fatalf("unexpected first warning: %s", plan.Warnings[0].ReasonCode)
	}
	if plan.Warnings[1].ReasonCode != "RUNSC_TRACE_FALLBACK_RUNC" {
		t.Fatalf("unexpected second warning: %s", plan.Warnings[1].ReasonCode)
	}
}

func TestPlanRunscDynamicFallbackSkipsHealthyRunsc(t *testing.T) {
	plan, ok := planRunscDynamicFallback("runsc", nil, parser.TraceHealth{
		TargetPhaseObserved:   true,
		TargetExitObserved:    true,
		TargetSyscallObserved: true,
	})
	if ok {
		t.Fatalf("did not expect fallback plan for healthy trace: %#v", plan)
	}
}

func TestPlanRunscDynamicFallbackSkipsRunc(t *testing.T) {
	_, ok := planRunscDynamicFallback("runc", nil, parser.TraceHealth{})
	if ok {
		t.Fatal("did not expect fallback plan for runc runtime")
	}
}
