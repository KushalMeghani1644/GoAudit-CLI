package project

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ManagerNPM  = "npm"
	ManagerPNPM = "pnpm"
	ManagerBun  = "bun"
)

type UpgradeMode string

const (
	UpgradeRefreshLock UpgradeMode = "refresh-lock"
	UpgradeNCU         UpgradeMode = "ncu"
	UpgradeUpdate      UpgradeMode = "update"
)

func ParseUpgradeMode(s string) (UpgradeMode, error) {
	switch UpgradeMode(s) {
	case UpgradeRefreshLock, UpgradeNCU, UpgradeUpdate:
		return UpgradeMode(s), nil
	default:
		return "", fmt.Errorf("unknown upgrade mode %q (use refresh-lock, ncu, or update)", s)
	}
}

type Project struct {
	Root    string
	Manager string
	Manifest packageManifest
}

type packageManifest struct {
	PackageManager string            `json:"packageManager"`
	Dependencies   map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces     json.RawMessage   `json:"workspaces"`
}

func Open(path string, managerOverride string) (*Project, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}

	manifestPath := filepath.Join(abs, "package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("package.json not found in project directory")
		}
		return nil, err
	}

	var manifest packageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	manager, err := detectManager(abs, manifest, managerOverride)
	if err != nil {
		return nil, err
	}

	return &Project{
		Root:     abs,
		Manager:  manager,
		Manifest: manifest,
	}, nil
}

func detectManager(root string, manifest packageManifest, override string) (string, error) {
	if override != "" {
		m := strings.ToLower(strings.TrimSpace(override))
		switch m {
		case ManagerNPM, ManagerPNPM, ManagerBun:
			return m, nil
		default:
			return "", fmt.Errorf("unknown manager %q (use npm, pnpm, or bun)", override)
		}
	}

	if pm := manifest.PackageManager; pm != "" {
		if idx := strings.Index(pm, "@"); idx > 0 {
			pm = pm[:idx]
		}
		switch strings.ToLower(pm) {
		case ManagerNPM, ManagerPNPM, ManagerBun:
			return strings.ToLower(pm), nil
		}
	}

	if fileExists(filepath.Join(root, "pnpm-lock.yaml")) {
		return ManagerPNPM, nil
	}
	if fileExists(filepath.Join(root, "bun.lockb")) || fileExists(filepath.Join(root, "bun.lock")) {
		return ManagerBun, nil
	}
	if fileExists(filepath.Join(root, "package-lock.json")) {
		return ManagerNPM, nil
	}
	if fileExists(filepath.Join(root, "yarn.lock")) {
		return "", errors.New("yarn.lock detected: scan-project supports npm, pnpm, and bun only; use goaudit scan with a yarn command or switch package managers")
	}

	return ManagerNPM, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
