package sandbox

import (
	"strings"
	"testing"
)

func TestAptPrepScriptSkipsWhenToolsPresent(t *testing.T) {
	if !strings.Contains(aptPrepScript, "command -v strace") {
		t.Fatal("expected conditional strace check")
	}
	if !strings.Contains(aptPrepScript, "command -v rsync") {
		t.Fatal("expected conditional rsync check")
	}
	if !strings.Contains(aptPrepScript, "apt-get update") {
		t.Fatal("expected apt-get when tools missing")
	}
}

func TestPrepScriptForRuntimeSkipsRunsc(t *testing.T) {
	if got := prepScriptForRuntime("runsc"); got != "" {
		t.Fatalf("expected runsc prep script to be empty, got %q", got)
	}
	if got := prepScriptForRuntime("runc"); got != aptPrepScript {
		t.Fatal("expected runc prep script to use apt bootstrap")
	}
}
