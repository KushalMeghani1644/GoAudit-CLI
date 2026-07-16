package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
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
		return "", diagnostic.New(
			fmt.Sprintf("Unknown upgrade mode %q.", s),
			diagnostic.Cause("The --upgrade-mode value must be one of: refresh-lock, ncu, or update."),
			diagnostic.Hint("Use --upgrade-mode refresh-lock for a lockfile refresh, --upgrade-mode ncu for npm-check-updates, or --upgrade-mode update for package-manager updates."),
		)
	}
}

type Project struct {
	Root     string
	Manager  string
	Manifest packageManifest
}

type packageManifest struct {
	PackageManager       string            `json:"packageManager"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

func Open(path string, managerOverride string) (*Project, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot resolve project path %q.", path),
			diagnostic.Cause("GoAudit could not turn the path into an absolute filesystem path."),
			diagnostic.Hint("Check that the path is valid for the current shell and try again."),
			diagnostic.Wrap(err),
		)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, diagnostic.New(
				fmt.Sprintf("Project path does not exist: %s.", abs),
				diagnostic.Cause("scan-project needs an existing JavaScript project directory."),
				diagnostic.Hint("Pass the directory that contains package.json."),
				diagnostic.Wrap(err),
			)
		}
		if os.IsPermission(err) {
			return nil, diagnostic.New(
				fmt.Sprintf("Cannot read project path: %s.", abs),
				diagnostic.Cause("The current user does not have permission to inspect the project directory."),
				diagnostic.Hint("Fix the directory permissions or run GoAudit as a user that can read the project."),
				diagnostic.Wrap(err),
			)
		}
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot inspect project path: %s.", abs),
			diagnostic.Cause("GoAudit could not read filesystem metadata for the project path."),
			diagnostic.Hint("Verify the path is accessible and try again."),
			diagnostic.Wrap(err),
		)
	}
	if !info.IsDir() {
		return nil, diagnostic.New(
			fmt.Sprintf("Project path is not a directory: %s.", abs),
			diagnostic.Cause("scan-project expects a directory, not a single file."),
			diagnostic.Hint("Pass the folder that contains package.json."),
		)
	}

	manifestPath := filepath.Join(abs, "package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, diagnostic.New(
				fmt.Sprintf("No package.json found in %s.", abs),
				diagnostic.Cause("scan-project only works from a JavaScript project root."),
				diagnostic.Hint("Run GoAudit from the project root or pass the directory that contains package.json."),
				diagnostic.Wrap(err),
			)
		}
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot read package.json in %s.", abs),
			diagnostic.Cause("GoAudit found package.json but could not read it."),
			diagnostic.Hint("Check package.json permissions and try again."),
			diagnostic.Wrap(err),
		)
	}

	var manifest packageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("package.json is not valid JSON: %s.", manifestPath),
			diagnostic.Cause("The JSON parser failed before GoAudit could detect dependencies or the package manager."),
			diagnostic.Hint("Fix the syntax in package.json, then rerun scan-project."),
			diagnostic.Wrap(err),
		)
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
			return "", diagnostic.New(
				fmt.Sprintf("Unknown package manager %q.", override),
				diagnostic.Cause("The --manager value must be one of: npm, pnpm, or bun."),
				diagnostic.Hint("Remove --manager to let GoAudit detect the lockfile, or pass --manager npm, --manager pnpm, or --manager bun."),
			)
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
		return "", diagnostic.New(
			"Yarn projects are not supported by scan-project yet.",
			diagnostic.Cause(fmt.Sprintf("Found yarn.lock in %s, but scan-project currently supports npm, pnpm, and bun.", root)),
			diagnostic.Hint("Convert the project to npm, pnpm, or bun (for example: npm install) and rerun scan-project."),
			diagnostic.Hint("Yarn is not supported by goaudit scan either (no yarn profile/image); do not use goaudit scan yarn install."),
		)
	}

	return ManagerNPM, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
