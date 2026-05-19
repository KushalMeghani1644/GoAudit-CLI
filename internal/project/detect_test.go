package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectManagerFromLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Manager != ManagerNPM {
		t.Fatalf("expected npm fallback, got %s", proj.Manager)
	}

	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), "lockfileVersion: 9\n")
	proj, err = Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Manager != ManagerPNPM {
		t.Fatalf("expected pnpm, got %s", proj.Manager)
	}
}

func TestDetectManagerFromPackageManagerField(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"packageManager":"bun@1.2.0"}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Manager != ManagerBun {
		t.Fatalf("expected bun, got %s", proj.Manager)
	}
}

func TestYarnLockRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "yarn.lock"), "# yarn lockfile v1\n")

	_, err := Open(root, "")
	if err == nil {
		t.Fatal("expected yarn.lock error")
	}
}

func TestManagerOverride(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), "{}\n")

	proj, err := Open(root, "pnpm")
	if err != nil {
		t.Fatal(err)
	}
	if proj.Manager != ManagerPNPM {
		t.Fatalf("expected override pnpm, got %s", proj.Manager)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
