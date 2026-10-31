package project

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestStageForSandboxOnlyAllowlistedInputs(t *testing.T) {
	root := t.TempDir()
	// Keep the expected list independent of the implementation: expanding the
	// allowlist must require an explicit change to this security regression.
	inputs := map[string]string{
		"package.json":        `{"name":"app","version":"1.0.0"}`,
		"package-lock.json":   `{"lockfileVersion":3}`,
		"npm-shrinkwrap.json": `{"lockfileVersion":3}`,
		"pnpm-lock.yaml":      "lockfileVersion: '9.0'\n",
		"bun.lock":            `{"lockfileVersion":1}`,
		"bun.lockb":           "\x00\x01binary-lock\xff",
	}
	for name, content := range inputs {
		mustWrite(t, filepath.Join(root, name), content)
	}
	for _, name := range []string{
		".env", ".env.local", ".npmrc", ".yarnrc", ".yarnrc.yml", "yarn.lock",
		"pnpm-workspace.yaml", "private-notes.txt", "credentials-with-an-unusual-name",
		"src/index.js", "patches/ordinary.txt", "patches/package.json",
		".yarn/releases/yarn.cjs", "packages/child/package.json",
		"node_modules/pkg/package.json", ".git/config", ".ssh/id_rsa",
	} {
		mustWrite(t, filepath.Join(root, name), "must never be staged")
	}

	stage, err := StageForSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if stage.Dir == root {
		t.Fatal("must mount a temporary stage, not the original project")
	}
	entries, err := os.ReadDir(stage.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for _, entry := range entries {
		got = append(got, entry.Name())
		if !entry.Type().IsRegular() {
			t.Fatalf("stage contains non-regular input %s", entry.Name())
		}
	}
	for name, content := range inputs {
		want = append(want, name)
		data, err := os.ReadFile(filepath.Join(stage.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != content {
			t.Fatalf("%s contents changed: %q", name, data)
		}
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staged files = %v, want exactly %v", got, want)
	}
	stage.Cleanup()
	stage.Cleanup() // Cleanup is safe to call more than once.
	if _, err := os.Stat(stage.Dir); !os.IsNotExist(err) {
		t.Fatalf("stage was not cleaned up: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil || string(data) != inputs["package.json"] {
		t.Fatalf("host manifest was modified: %q, %v", data, err)
	}
}

func TestStageForSandboxWithoutLockfiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	stage, err := StageForSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	entries, err := os.ReadDir(stage.Dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "package.json" {
		t.Fatalf("expected only package.json, got %v, %v", entries, err)
	}
}

func TestStageForSandboxSkipsSymlinkedInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require elevated permissions")
	}
	root, external := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	mustWrite(t, filepath.Join(external, "secret"), "not a lockfile")
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lock", "bun.lockb"} {
		if err := os.Symlink(filepath.Join(external, "secret"), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(external, filepath.Join(root, "patches")); err != nil {
		t.Fatal(err)
	}
	stage, err := StageForSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	entries, err := os.ReadDir(stage.Dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "package.json" {
		t.Fatalf("symlinked inputs must not be staged: %v, %v", entries, err)
	}
	if err := os.Remove(filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, "secret"), filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if stage, err := StageForSandbox(root); err == nil || stage != nil {
		t.Fatalf("symlinked package.json must fail: %v, %v", stage, err)
	}
}

func TestStageForSandboxInvalidInputsCleanUp(t *testing.T) {
	for _, kind := range []string{"missing root", "file root", "missing manifest", "directory manifest"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			t.Setenv("TMP", temp)
			t.Setenv("TEMP", temp)
			switch kind {
			case "missing root":
				root = filepath.Join(root, "missing")
			case "file root":
				root = filepath.Join(root, "file")
				mustWrite(t, root, "not a directory")
			case "directory manifest":
				if err := os.Mkdir(filepath.Join(root, "package.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stage, err := StageForSandbox(root)
			if err == nil || stage != nil {
				t.Fatalf("expected failure, got %v, %v", stage, err)
			}
			entries, err := os.ReadDir(temp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed stage leaked temporary files: %v, %v", entries, err)
			}
		})
	}
}

func TestStageForSandboxCopyFailureCleansUp(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix file permissions enforced for an unprivileged user")
	}
	root, temp := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", temp)
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	lock := filepath.Join(root, "package-lock.json")
	mustWrite(t, lock, "{}")
	if err := os.Chmod(lock, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lock, 0o644) })
	stage, err := StageForSandbox(root)
	if err == nil || stage != nil || !strings.Contains(err.Error(), "copy package-lock.json") {
		t.Fatalf("expected copy failure, got %v, %v", stage, err)
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial stage was not removed: %v, %v", entries, err)
	}
}

func TestStageForSandboxSkipsDirectoryLockfile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	mustWrite(t, filepath.Join(root, "bun.lock", "secret"), "do not traverse")
	stage, err := StageForSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := os.Lstat(filepath.Join(stage.Dir, "bun.lock")); !os.IsNotExist(err) {
		t.Fatalf("directory lockfile must not enter stage: %v", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
