package project

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// sandboxInputFiles is the complete allowlist of project files exposed to
// install scripts. Do not add directories or credential-bearing configuration
// (such as .npmrc): staging does not attempt to identify or redact secrets.
var sandboxInputFiles = []string{
	"package.json",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"pnpm-lock.yaml",
	"bun.lock",
	"bun.lockb",
}

// StageResult holds a temporary manifests-only directory for sandbox mounting.
type StageResult struct {
	Dir     string
	Cleanup func()
}

// StageForSandbox copies only root package.json and supported lockfiles into a
// temporary directory. The caller must call Cleanup when done and must mount
// this directory, never the live project root. Symlinks and non-regular files
// are not install inputs; package.json must be a regular file.
func StageForSandbox(projectRoot string) (*StageResult, error) {
	abs, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat project root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("project root is not a directory: %s", abs)
	}

	stage, err := os.MkdirTemp("", "goaudit-project-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create stage dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stage) }

	for _, name := range sandboxInputFiles {
		src := filepath.Join(abs, name)
		info, err := os.Lstat(src)
		if os.IsNotExist(err) && name != "package.json" {
			continue
		}
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("inspect %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			if name != "package.json" {
				continue
			}
			cleanup()
			return nil, fmt.Errorf("package.json must be a regular file in %s", abs)
		}
		if err := copyFile(src, filepath.Join(stage, name)); err != nil {
			cleanup()
			return nil, fmt.Errorf("copy %s: %w", name, err)
		}
	}

	return &StageResult{Dir: stage, Cleanup: cleanup}, nil
}

func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to copy non-regular file %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	openedInfo, err := in.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("staging input changed while opening %s", src)
	}
	// Staged inputs are data, not executables, and need to be readable by the
	// unprivileged sandbox user regardless of the host file's permissions.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
