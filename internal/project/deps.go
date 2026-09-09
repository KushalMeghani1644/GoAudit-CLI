package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
)

// DepSpec is a package name with an optional version/range for static analysis.
type DepSpec struct {
	Name    string
	Version string // may be empty, a range, or a concrete resolved version
}

// SpecString returns name or name@version for registry analysis.
func (d DepSpec) SpecString() string {
	if d.Version == "" {
		return d.Name
	}
	return d.Name + "@" + d.Version
}

func (p *Project) ListDirectDeps() []string {
	specs := p.ListDirectDepSpecs()
	names := make([]string, 0, len(specs))
	seen := map[string]struct{}{}
	for _, s := range specs {
		if _, ok := seen[s.Name]; ok {
			continue
		}
		seen[s.Name] = struct{}{}
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// ListDirectDepSpecs returns direct dependencies (and workspace package deps)
// as name + version/range pairs from package.json files.
func (p *Project) ListDirectDepSpecs() []DepSpec {
	byName := map[string]DepSpec{}
	collectDepSpecs(p.Manifest.Dependencies, byName)
	collectDepSpecs(p.Manifest.DevDependencies, byName)
	collectDepSpecs(p.Manifest.OptionalDependencies, byName)

	for _, dir := range p.workspacePackageDirs() {
		manifestPath := filepath.Join(dir, "package.json")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var m packageManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		collectDepSpecs(m.Dependencies, byName)
		collectDepSpecs(m.DevDependencies, byName)
		collectDepSpecs(m.OptionalDependencies, byName)
	}

	out := make([]DepSpec, 0, len(byName))
	for _, d := range byName {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func collectDepSpecs(deps map[string]string, byName map[string]DepSpec) {
	for name, ver := range deps {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		// Prefer a concrete version if we later overwrite with lock data.
		byName[name] = DepSpec{Name: name, Version: strings.TrimSpace(ver)}
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

func stripJSONTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// ListTransitiveDeps returns package names from the selected manager's lockfile.
func (p *Project) ListTransitiveDeps() ([]string, error) {
	specs, err := p.ListTransitiveDepSpecs()
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(specs))
	for _, s := range specs {
		if s.Name != "" {
			names[s.Name] = struct{}{}
		}
	}
	return sortedNames(names), nil
}

// ListTransitiveDepSpecs returns resolved packages from the selected manager's lockfile.
// Returns (nil, nil) when no supported lockfile is present.
func (p *Project) ListTransitiveDepSpecs() ([]DepSpec, error) {
	switch p.Manager {
	case ManagerNPM:
		specs, err, _ := p.tryNPMLockSpecs()
		return specs, err
	case ManagerPNPM:
		specs, err, _ := p.tryPNPMLockSpecs()
		return specs, err
	case ManagerBun:
		specs, err, _ := p.tryBunLockSpecs()
		return specs, err
	}
	return nil, nil
}

// TransitiveLockfileStatus describes lockfile availability for --include-transitive.
func (p *Project) TransitiveLockfileStatus() (found bool, kind string) {
	switch p.Manager {
	case ManagerNPM:
		if fileExists(filepath.Join(p.Root, "package-lock.json")) {
			return true, "package-lock.json"
		}
	case ManagerPNPM:
		if fileExists(filepath.Join(p.Root, "pnpm-lock.yaml")) {
			return true, "pnpm-lock.yaml"
		}
	case ManagerBun:
		switch {
		case fileExists(filepath.Join(p.Root, "bun.lock")):
			return true, "bun.lock"
		case fileExists(filepath.Join(p.Root, "bun.lockb")):
			// Binary lockfile is not parsed; treat as present but unsupported.
			return true, "bun.lockb"
		}
	}
	return false, ""
}

func (p *Project) tryNPMLockSpecs() ([]DepSpec, error, bool) {
	lockPath := filepath.Join(p.Root, "package-lock.json")
	if !fileExists(lockPath) {
		return nil, nil, false
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot read package-lock.json in %s.", p.Root),
			diagnostic.Cause("GoAudit needs package-lock.json to include transitive dependencies."),
			diagnostic.Hint("Check package-lock.json permissions, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		), true
	}

	type npmLockDependency struct {
		Version      string                       `json:"version"`
		Dependencies map[string]npmLockDependency `json:"dependencies"`
	}
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]npmLockDependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("package-lock.json is not valid JSON: %s.", lockPath),
			diagnostic.Cause("GoAudit could not parse the lockfile to list transitive dependencies."),
			diagnostic.Hint("Regenerate the lockfile with npm install, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		), true
	}

	bySpec := map[string]DepSpec{}
	for path, pkg := range lock.Packages {
		if path == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = lockPackageNameFromPath(path)
		}
		if name == "" {
			continue
		}
		spec := DepSpec{Name: name, Version: strings.TrimSpace(pkg.Version)}
		bySpec[depSpecKey(spec)] = spec
	}
	// Older lockfileVersion 1 style, whose dependency graph is nested.
	var addLegacyDeps func(map[string]npmLockDependency)
	addLegacyDeps = func(deps map[string]npmLockDependency) {
		for name, pkg := range deps {
			name = strings.TrimSpace(name)
			if name != "" {
				spec := DepSpec{Name: name, Version: strings.TrimSpace(pkg.Version)}
				bySpec[depSpecKey(spec)] = spec
			}
			addLegacyDeps(pkg.Dependencies)
		}
	}
	addLegacyDeps(lock.Dependencies)
	return sortedDepSpecs(bySpec), nil, true
}

var (
	pnpmPkgKeyQuoted = regexp.MustCompile(`(?m)^ {2}'([^']+)'\s*:`)
	pnpmPkgKeyPlain  = regexp.MustCompile(`(?m)^ {2}(/?[@\w.//+:-]+@[^\s]+)\s*:`)
)

func (p *Project) tryPNPMLockSpecs() ([]DepSpec, error, bool) {
	lockPath := filepath.Join(p.Root, "pnpm-lock.yaml")
	if !fileExists(lockPath) {
		return nil, nil, false
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot read pnpm-lock.yaml in %s.", p.Root),
			diagnostic.Cause("GoAudit needs pnpm-lock.yaml to include transitive dependencies."),
			diagnostic.Hint("Check pnpm-lock.yaml permissions, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		), true
	}

	// Parse from the packages: section when present. Package keys are indented,
	// which distinguishes them from top-level YAML keys.
	text := string(data)
	section := text
	if idx := strings.Index(text, "\npackages:"); idx >= 0 {
		section = text[idx+1:]
	}

	bySpec := map[string]DepSpec{}
	for _, re := range []*regexp.Regexp{pnpmPkgKeyQuoted, pnpmPkgKeyPlain} {
		for _, m := range re.FindAllStringSubmatch(section, -1) {
			if len(m) < 2 {
				continue
			}
			name, ver := parsePnpmPackageKey(m[1])
			if name == "" {
				continue
			}
			spec := DepSpec{Name: name, Version: ver}
			bySpec[depSpecKey(spec)] = spec
		}
	}
	return sortedDepSpecs(bySpec), nil, true
}

// parsePnpmPackageKey parses keys like "/lodash@4.17.21", "/@scope/pkg@1.0.0(peer@1)", "lodash@4.17.21".
func parsePnpmPackageKey(key string) (name, version string) {
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "'\"")
	key = strings.TrimPrefix(key, "/")
	if key == "" || key == "." {
		return "", ""
	}
	// Aliases such as foo@npm:bar@1.0.0 do not identify the package named by
	// the key. Skip them instead of issuing an invalid registry package name.
	if strings.Contains(key, "npm:") {
		return "", ""
	}
	// Drop peer dependency suffix: name@version(peer@x)
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	// Path-style nesting: node_modules/.pnpm/... skip non package keys
	if strings.Contains(key, "node_modules/") {
		return "", ""
	}
	if strings.HasPrefix(key, "@") {
		// @scope/name@version
		if strings.Count(key, "@") < 2 {
			return key, ""
		}
		last := strings.LastIndex(key, "@")
		return key[:last], key[last+1:]
	}
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

func (p *Project) tryBunLockSpecs() ([]DepSpec, error, bool) {
	// Prefer text bun.lock; binary bun.lockb is not parsed.
	lockPath := filepath.Join(p.Root, "bun.lock")
	if !fileExists(lockPath) {
		if fileExists(filepath.Join(p.Root, "bun.lockb")) {
			// Present but unsupported — signal via empty result; caller can warn.
			return nil, nil, true
		}
		return nil, nil, false
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("Cannot read bun.lock in %s.", p.Root),
			diagnostic.Cause("GoAudit needs bun.lock to include transitive dependencies."),
			diagnostic.Hint("Check bun.lock permissions, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		), true
	}

	// bun.lock is JSONC: normalize comments and trailing commas before decoding.
	var lock struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(normalizeJSONC(data), &lock); err != nil {
		return nil, diagnostic.New(
			fmt.Sprintf("bun.lock is not valid JSONC: %s.", lockPath),
			diagnostic.Cause("GoAudit could not parse the lockfile to list transitive dependencies."),
			diagnostic.Hint("Regenerate the lockfile with bun install, or rerun without --include-transitive."),
			diagnostic.Wrap(err),
		), true
	}

	bySpec := map[string]DepSpec{}
	for key, raw := range lock.Packages {
		name := strings.TrimSpace(key)
		// Keys may be "lodash" or "@scope/pkg".
		if name == "" {
			continue
		}
		ver := ""
		// Value formats vary: array ["lodash@4.17.21", ...] or object {"version":"..."}.
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
			var first string
			if err := json.Unmarshal(arr[0], &first); err == nil {
				if _, v := splitNameVersion(first); v != "" {
					ver = v
				}
			}
		} else {
			var obj struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(raw, &obj); err == nil {
				ver = strings.TrimSpace(obj.Version)
			}
		}
		// Normalize name if key embeds version.
		if n, v := splitNameVersion(name); n != "" && v != "" {
			name, ver = n, v
		}
		spec := DepSpec{Name: name, Version: ver}
		bySpec[depSpecKey(spec)] = spec
	}
	return sortedDepSpecs(bySpec), nil, true
}

// normalizeJSONC removes JSONC comments and trailing commas while preserving
// string literals, making the result suitable for encoding/json.
func normalizeJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(data) && data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
			continue
		}
		if c == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			if i+1 < len(data) {
				i++
			}
			out = append(out, ' ')
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return stripJSONTrailingCommas(out)
}

func splitNameVersion(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	if strings.HasPrefix(spec, "@") {
		if strings.Count(spec, "@") > 1 {
			last := strings.LastIndex(spec, "@")
			return spec[:last], spec[last+1:]
		}
		return spec, ""
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, ""
}

func sortedDepSpecs(byName map[string]DepSpec) []DepSpec {
	out := make([]DepSpec, 0, len(byName))
	for _, d := range byName {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func depSpecKey(spec DepSpec) string {
	return spec.Name + "\x00" + spec.Version
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

// ListDepsForStatic returns package specs for registry static analysis.
// When includeTransitive is true, lockfile packages are preferred (resolved versions).
// When a lockfile is missing, only direct deps are returned (callers should warn).
func (p *Project) ListDepsForStatic(includeTransitive bool) ([]string, error) {
	specs, err := p.ListDepSpecsForStatic(includeTransitive)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.SpecString())
	}
	return out, nil
}

// ListDepSpecsForStatic is like ListDepsForStatic but keeps structured specs.
func (p *Project) ListDepSpecsForStatic(includeTransitive bool) ([]DepSpec, error) {
	direct := p.ListDirectDepSpecs()
	if !includeTransitive {
		return direct, nil
	}

	transitive, err := p.ListTransitiveDepSpecs()
	if err != nil {
		return nil, err
	}
	if len(transitive) == 0 {
		// No usable lock entries — fall back to direct so scan still does something.
		return direct, nil
	}

	// Preserve every resolved lockfile version; include direct deps missing from lock.
	bySpec := map[string]DepSpec{}
	lockedNames := map[string]struct{}{}
	for _, d := range transitive {
		bySpec[depSpecKey(d)] = d
		lockedNames[d.Name] = struct{}{}
	}
	for _, d := range direct {
		if _, ok := lockedNames[d.Name]; !ok {
			bySpec[depSpecKey(d)] = d
		}
	}
	return sortedDepSpecs(bySpec), nil
}

// workspacePackageDirs resolves workspace package directories from package.json.
func (p *Project) workspacePackageDirs() []string {
	patterns := workspacePatterns(p.Manifest.Workspaces)
	if len(patterns) == 0 {
		return nil
	}
	var dirs []string
	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// Only support simple globs like "packages/*" or exact relative dirs.
		matches, err := filepath.Glob(filepath.Join(p.Root, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			if !fileExists(filepath.Join(m, "package.json")) {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			dirs = append(dirs, m)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func workspacePatterns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Packages
	}
	return nil
}
