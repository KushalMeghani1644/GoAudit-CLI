package project

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Minimal install inputs copied into the sandbox by default.
// Intentionally excludes .npmrc (often holds registry tokens) and source trees.
var minimalStageFiles = []string{
	"package.json",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"pnpm-lock.yaml",
	"pnpm-workspace.yaml",
	"bun.lock",
	"bun.lockb",
	"yarn.lock",
	".yarnrc.yml",
	".yarnrc",
}

// Directories that may be needed for install (patches, yarn releases) but are
// less likely to hold secrets than the full project tree.
var minimalStageDirs = []string{
	"patches",
	".yarn",
}

// secretPathFragments are path segments/names that must never enter a full-tree stage.
var secretPathFragments = []string{
	".env",
	".aws",
	".ssh",
	".kube",
	".git-credentials",
	".npmrc",
	".yarnrc",
	".yarnrc.yml",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
}

// StageOptions controls how a project is prepared for sandbox mounting.
type StageOptions struct {
	// FullTree copies the project tree with secret paths excluded.
	// When false (default), only package manifests/lockfiles and a few install dirs are copied.
	FullTree bool
}

// StageResult is a temporary directory safe to bind-mount into the sandbox.
type StageResult struct {
	Dir      string
	FullTree bool
	Cleanup  func()
}

// StageForSandbox copies a sanitized subset (or filtered full tree) of the project
// into a temporary directory. The caller must call Cleanup when done.
//
// The returned directory is what should be bind-mounted — never the live project
// root — so install scripts cannot read real .env / keys via /project-ro.
func StageForSandbox(projectRoot string, opts StageOptions) (*StageResult, error) {
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

	if opts.FullTree {
		if err := copyFilteredTree(abs, stage); err != nil {
			cleanup()
			return nil, err
		}
	} else {
		if err := copyMinimalStage(abs, stage); err != nil {
			cleanup()
			return nil, err
		}
	}

	return &StageResult{
		Dir:      stage,
		FullTree: opts.FullTree,
		Cleanup:  cleanup,
	}, nil
}

func copyMinimalStage(srcRoot, dstRoot string) error {
	for _, name := range minimalStageFiles {
		src := filepath.Join(srcRoot, name)
		if isSecretPath(name, name) || !isRegularFile(src) {
			continue
		}
		if err := copyFile(src, filepath.Join(dstRoot, name)); err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
	}
	for _, name := range minimalStageDirs {
		src := filepath.Join(srcRoot, name)
		info, err := os.Lstat(src)
		if err != nil || !info.IsDir() {
			continue
		}
		if err := copyFilteredTree(src, filepath.Join(dstRoot, name)); err != nil {
			return fmt.Errorf("copy dir %s: %w", name, err)
		}
	}
	// Ensure package.json exists — install commands require it.
	if !isRegularFile(filepath.Join(dstRoot, "package.json")) {
		return fmt.Errorf("package.json missing from project root %s", srcRoot)
	}
	return nil
}

func copyFilteredTree(srcRoot, dstRoot string) error {
	return filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dstRoot, 0o755)
		}

		// Always skip VCS and dependency trees.
		base := d.Name()
		if base == ".git" || base == "node_modules" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if isSecretPath(rel, base) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		dst := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			// Do not follow symlinks or copy irregular files; opening a FIFO can
			// block indefinitely and device files must not enter the sandbox.
			return nil
		}
		return copyFile(path, dst)
	})
}

func isSecretPath(rel, base string) bool {
	lowerRel := strings.ToLower(filepath.ToSlash(rel))
	lowerBase := strings.ToLower(base)

	// Exact / prefix secret basenames and .env variants.
	if strings.HasPrefix(lowerBase, ".env") {
		return true
	}
	if strings.HasSuffix(lowerBase, ".pem") || strings.HasSuffix(lowerBase, ".key") {
		return true
	}
	for _, frag := range secretPathFragments {
		if lowerBase == frag || strings.HasPrefix(lowerBase, frag) {
			return true
		}
		// Directory segment match: ".ssh/id_rsa", "foo/.aws/credentials"
		if strings.Contains(lowerRel, "/"+frag+"/") || strings.HasPrefix(lowerRel, frag+"/") || lowerRel == frag {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to copy non-regular file %s", src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err = in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// isRegularFile reports whether path names a regular file without following
// symlinks. Staging must never open a symlink, FIFO, socket, or device file.
func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
