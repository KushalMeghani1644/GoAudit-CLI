package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		return nil, err
	}

	var lock struct {
		Packages map[string]struct {
			Name string `json:"name"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
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
