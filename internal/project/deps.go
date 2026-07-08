package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
)

func (p *Project) ListDirectDeps() []string {
	names := make(map[string]struct{})
	collectDepNames(p.Manifest.Dependencies, names)
	collectDepNames(p.Manifest.DevDependencies, names)
	collectDepNames(p.Manifest.OptionalDependencies, names)
	return sortedNames(names)
}

func collectDepNames(deps map[string]string, names map[string]struct{}) {
	for name := range deps {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		names[name] = struct{}{}
	}
}

func sortedNames(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (p *Project) ListTransitiveDeps() ([]string, error) {
	lockPath := filepath.Join(p.Root, "package-lock.json")
	if !fileExists(lockPath) {
		return nil, nil
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot read package-lock.json in %s.", p.Root),
			diagnostic.Cause("GoAudit needs package-lock.json to include transitive dependencies."),
			diagnostic.Hint("Check package-lock.json permissions, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		)
	}

	var lock struct {
		Packages map[string]struct {
			Name string `json:"name"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("package-lock.json is not valid JSON: %s.", lockPath),
			diagnostic.Cause("GoAudit could not parse the lockfile to list transitive dependencies."),
			diagnostic.Hint("Regenerate the lockfile with npm install, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		)
	}

	names := make(map[string]struct{})
	for path, pkg := range lock.Packages {
		if path == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = lockPackageNameFromPath(path)
		}
		if name != "" {
			names[name] = struct{}{}
		}
	}
	return sortedNames(names), nil
}

func lockPackageNameFromPath(path string) string {
	const prefix = "node_modules/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if strings.Contains(rest, "node_modules/") {
		idx := strings.LastIndex(rest, "node_modules/")
		rest = rest[idx+len("node_modules/"):]
	}
	return rest
}

func (p *Project) ListDepsForStatic(includeTransitive bool) ([]string, error) {
	direct := p.ListDirectDeps()
	if !includeTransitive {
		return direct, nil
	}

	transitive, err := p.ListTransitiveDeps()
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})
	for _, n := range direct {
		names[n] = struct{}{}
	}
	for _, n := range transitive {
		names[n] = struct{}{}
	}
	return sortedNames(names), nil
}
