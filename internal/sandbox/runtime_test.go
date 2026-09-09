package sandbox

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
	"github.com/docker/docker/api/types/system"
)

func TestRuntimeFromDockerInfo(t *testing.T) {
	if got := RuntimeFromDockerInfo(nil); got != "" {
		t.Fatalf("nil runtimes: got %q", got)
	}
	if got := RuntimeFromDockerInfo(map[string]system.RuntimeWithStatus{"runc": {}}); got != "" {
		t.Fatalf("runc only: got %q", got)
	}
	if got := RuntimeFromDockerInfo(map[string]system.RuntimeWithStatus{"runsc": {}, "runc": {}}); got != "runsc" {
		t.Fatalf("runsc registered: got %q", got)
	}
}

func TestNodeSandboxImageUsesGHCR(t *testing.T) {
	if !strings.HasPrefix(NodeSandboxImage, "ghcr.io/kushalmeghani1644/goaudit-node-sandbox:") {
		t.Fatalf("unexpected node sandbox image: %s", NodeSandboxImage)
	}
}

func TestGVisorSetupURLLinksToDocumentation(t *testing.T) {
	if !strings.HasPrefix(GVisorSetupURL, "https://github.com/KushalMeghani1644/GoAudit-CLI#") {
		t.Fatalf("unexpected gVisor setup URL: %s", GVisorSetupURL)
	}
}

func TestRequireRunscRejectsRuncOnly(t *testing.T) {
	err := RequireRunsc(map[string]system.RuntimeWithStatus{"runc": {}})
	if err == nil {
		t.Fatal("expected runc-only Docker configuration to be rejected")
	}
	out := diagnostic.Format(err)
	for _, want := range []string{
		"gVisor (runsc) is required",
		"will not fall back to runc",
		GVisorSetupURL,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diagnostic missing %q:\n%s", want, out)
		}
	}
}

func TestRequireRunscAcceptsRegisteredRuntime(t *testing.T) {
	if err := RequireRunsc(map[string]system.RuntimeWithStatus{"runsc": {}, "runc": {}}); err != nil {
		t.Fatalf("registered runsc rejected: %v", err)
	}
}
