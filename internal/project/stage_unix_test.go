//go:build unix

package project

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStageForSandboxSkipsFIFO(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	if err := syscall.Mkfifo(filepath.Join(root, "package-lock.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := StageForSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := os.Lstat(filepath.Join(stage.Dir, "package-lock.json")); !os.IsNotExist(err) {
		t.Fatalf("FIFO must not enter stage: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "package.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if stage, err := StageForSandbox(root); err == nil || stage != nil {
		t.Fatalf("FIFO package.json must fail without opening: %v, %v", stage, err)
	}
}
