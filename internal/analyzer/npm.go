package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

var npmRegistryBaseURL = "https://registry.npmjs.org"

const (
	registryWorkerCount = 8
	registryStagger     = 50 * time.Millisecond
	// cliRegistrySpecCap limits host-side registry metadata fetches for CLI install
	// commands. When exceeded, remaining specs are skipped with an explicit warning.
	cliRegistrySpecCap = 25
)

type npmMetadata struct {
	DistTags map[string]string `json:"dist-tags"`
	Time     struct {
		Created string `json:"created"`
	} `json:"time"`
	Versions map[string]struct {
		Scripts map[string]string `json:"scripts"`
	} `json:"versions"`
}

func AnalyzeJSPackageManagers(command string) []report.Finding {
	var findings []report.Finding
	findings = append(findings, AnalyzeNPMInstall(command)...)
	findings = append(findings, analyzePNPMInstall(command)...)
	findings = append(findings, analyzeBUNAdd(command)...)
	if len(findings) == 0 {
		if f, ok := packageParseIncompleteFinding(command); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func AnalyzeNPMInstall(command string) []report.Finding {
	specs := extractInstallSpecs(command, "npm", []string{"install", "i"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "npm", cliRegistrySpecCap)
}

func analyzePNPMInstall(command string) []report.Finding {
	specs := extractInstallSpecs(command, "pnpm", []string{"add", "install", "i"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "pnpm", cliRegistrySpecCap)
}

func analyzeBUNAdd(command string) []report.Finding {
	specs := extractInstallSpecs(command, "bun", []string{"add"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "bun", cliRegistrySpecCap)
}

// packageParseIncompleteFinding emits an honest coverage warning when the command
// looks like a package-manager install but package extraction found nothing
// (pipes, command substitution, heavy quoting, unknown wrappers).
func packageParseIncompleteFinding(command string) (report.Finding, bool) {
	lc := strings.ToLower(command)
	looksLikeInstall := (strings.Contains(lc, "npm") && (strings.Contains(lc, " install") || strings.Contains(lc, " i ") || strings.HasSuffix(lc, " i"))) ||
		(strings.Contains(lc, "pnpm") && (strings.Contains(lc, " add") || strings.Contains(lc, " install"))) ||
		(strings.Contains(lc, "bun") && strings.Contains(lc, " add"))
	if !looksLikeInstall {
		return report.Finding{}, false
	}
	// If we can extract any specs, parsing worked.
	if len(extractInstallSpecs(command, "npm", []string{"install", "i"})) > 0 ||
		len(extractInstallSpecs(command, "pnpm", []string{"add", "install", "i"})) > 0 ||
		len(extractInstallSpecs(command, "bun", []string{"add"})) > 0 {
		return report.Finding{}, false
	}
	// Bare "npm install" with no package args is valid (uses package.json) — not incomplete.
	if !strings.ContainsAny(command, "|$`") && !strings.Contains(command, "$(") {
		// Still may be wrappers we don't understand with package args.
		// Only warn when shell metacharacters suggest bypass.
		return report.Finding{}, false
	}
	return report.Finding{
		Severity:   report.SeverityWarning,
		Type:       "policy",
		ReasonCode: "PACKAGE_PARSE_INCOMPLETE",
		Path:       command,
		Confidence: 70,
		Evidence:   "Package-manager install command detected but package specs could not be extracted (quoting, pipes, substitutions, or unknown wrappers); registry static analysis skipped for specs",
	}, true
}

func AnalyzeRegistryPackages(pkgs []string, manager string) []report.Finding {
	specs := make([]string, 0, len(pkgs))
	seen := make(map[string]struct{})
	for _, pkg := range pkgs {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if _, ok := seen[pkg]; ok {
			continue
		}
		seen[pkg] = struct{}{}
		specs = append(specs, pkg)
	}
	sort.Strings(specs)
	return analyzeRegistryBackedSpecs(specs, manager, 0)
}

func analyzeRegistryBackedSpecs(specs []string, manager string, cap int) []report.Finding {
	if len(specs) == 0 {
		return nil
	}

	var findings []report.Finding
	if cap > 0 && len(specs) > cap {
		dropped := specs[cap:]
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       manager,
			ReasonCode: "STATIC_COVERAGE_LIMIT",
			Path:       strings.Join(dropped, ","),
			Confidence: 90,
			Evidence:   fmt.Sprintf("Static registry analysis checked the first %d package spec(s); skipped %d more: %s", cap, len(dropped), strings.Join(dropped, ", ")),
		})
		specs = specs[:cap]
	}

	client := &http.Client{Timeout: 8 * time.Second}
	jobs := make(chan string)
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		jobSeq atomic.Uint64
	)

	workers := registryWorkerCount
	if len(specs) < workers {
		workers = len(specs)
	}
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range jobs {
				seq := jobSeq.Add(1)
				time.Sleep(time.Duration(seq) * registryStagger)
				pkgFindings := analyzeRegistrySpec(client, spec, manager)
				if len(pkgFindings) == 0 {
					continue
				}
				mu.Lock()
				findings = append(findings, pkgFindings...)
				mu.Unlock()
			}
		}()
	}

	for _, spec := range specs {
		jobs <- spec
	}
	close(jobs)
	wg.Wait()

	return findings
}

func analyzeRegistrySpec(client *http.Client, spec, manager string) []report.Finding {
	var findings []report.Finding
	if isLocalPathSpec(spec) {
		return analyzeLocalPackage(spec, manager)
	}
	if isNonRegistryNpmSpec(spec) {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       manager,
			ReasonCode: managerReason(manager, "NON_REGISTRY_SOURCE"),
			Path:       spec,
			Confidence: 85,
			Evidence:   "Package source is not a standard npm registry reference",
		})
		return findings
	}

	pkg, requested := splitPackageSpec(spec)
	if pkg == "" {
		return nil
	}
	meta, err := fetchNPMMetadata(client, pkg)
	if err != nil {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       manager,
			ReasonCode: managerReason(manager, "INCONCLUSIVE_METADATA"),
			Path:       pkg,
			Confidence: 45,
			Evidence:   err.Error(),
		})
		return findings
	}

	version, versionEvidence, approximate := selectVersionToAnalyze(meta, requested)
	if approximate {
		path := pkg
		if requested != "" {
			path = pkg + "@" + requested
		}
		findings = append(findings, report.Finding{
			Severity:   report.SeverityInfo,
			Type:       manager,
			ReasonCode: managerReason(manager, "VERSION_RESOLUTION_APPROXIMATE"),
			Path:       path,
			Confidence: 60,
			Evidence:   versionEvidence,
		})
	}
	if version != "" {
		if verMeta, ok := meta.Versions[version]; ok {
			lifecycleScripts := []string{"preinstall", "install", "postinstall", "prepare"}
			foundLifecycle := false
			for _, scriptName := range lifecycleScripts {
				scriptContent, exists := verMeta.Scripts[scriptName]
				if !exists {
					continue
				}
				if !foundLifecycle {
					findings = append(findings, report.Finding{
						Severity:   report.SeverityWarning,
						Type:       manager,
						ReasonCode: managerReason(manager, "LIFECYCLE_SCRIPT_METADATA"),
						Path:       pkg + "@" + version,
						Confidence: 80,
						Evidence:   fmt.Sprintf("Package version defines %s script (%s)", scriptName, versionEvidence),
					})
					foundLifecycle = true
				}
				contentFindings := analyzeScriptBody(
					fmt.Sprintf("%s@%s:%s", pkg, version, scriptName),
					scriptContent,
				)
				for i := range contentFindings {
					contentFindings[i].Type = manager
					contentFindings[i].ReasonCode = managerReason(manager, "LIFECYCLE_"+contentFindings[i].ReasonCode)
				}
				findings = append(findings, contentFindings...)
			}
		} else if requested != "" {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityInfo,
				Type:       manager,
				ReasonCode: managerReason(manager, "VERSION_NOT_IN_METADATA"),
				Path:       pkg + "@" + requested,
				Confidence: 40,
				Evidence:   versionEvidence,
			})
		}
	}

	if meta.Time.Created != "" {
		createdAt, err := time.Parse(time.RFC3339, meta.Time.Created)
		if err == nil && time.Since(createdAt) < 14*24*time.Hour {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       manager,
				ReasonCode: managerReason(manager, "RECENT_PACKAGE"),
				Path:       pkg,
				Confidence: 70,
				Evidence:   "Package was created recently on npm registry",
			})
		}
	}
	return findings
}

// splitPackageSpec returns the package name and optional version/range/tag from a
// install spec such as "lodash@4.17.21", "@scope/pkg@^1.0.0", or "lodash".
// npm alias specs ("alias@npm:actual@1.2.3") are resolved to the actual
// package so registry analysis targets what npm really installs.
func splitPackageSpec(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	if strings.HasPrefix(spec, "npm:") {
		spec = strings.TrimPrefix(spec, "npm:")
	}
	if idx := strings.Index(spec, "@npm:"); idx >= 0 && idx+5 < len(spec) {
		return splitPackageSpec(spec[idx+len("@npm:"):])
	}
	if strings.HasPrefix(spec, "@") {
		if strings.Count(spec, "@") > 1 {
			last := strings.LastIndex(spec, "@")
			if last > 0 {
				return spec[:last], spec[last+1:]
			}
		}
		return spec, ""
	}
	if idx := strings.Index(spec, "@"); idx > 0 {
		return spec[:idx], spec[idx+1:]
	}
	return spec, ""
}

// isConcreteVersion reports whether v looks like an exact registry version
// (not a range/tag with operators).
func isConcreteVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.ContainsAny(v, "<>^=~*| ") {
		return false
	}
	// Dist-tags like "latest" / "next" are not concrete versions.
	if v[0] < '0' || v[0] > '9' {
		return false
	}
	return true
}

// selectVersionToAnalyze picks which package version's lifecycle scripts to inspect.
// approximate is true when the analyzer fell back to dist-tags.latest for a range
// or missing concrete version (not when a named dist-tag resolved cleanly).
func selectVersionToAnalyze(meta *npmMetadata, requested string) (version, evidence string, approximate bool) {
	latest := meta.DistTags["latest"]
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if latest == "" {
			return "", "no version available in registry metadata", false
		}
		// No version in the install spec: dist-tags.latest is the conventional
		// CLI default (npm install pkg). Not marked approximate — ranges are.
		return latest, "no version specified; analyzed dist-tags.latest", false
	}
	if isConcreteVersion(requested) {
		if _, ok := meta.Versions[requested]; ok {
			return requested, "analyzed requested version " + requested, false
		}
		if latest != "" {
			return latest, fmt.Sprintf("requested version %s not present in metadata; fell back to dist-tags.latest %s", requested, latest), true
		}
		return "", fmt.Sprintf("requested version %s not present in metadata", requested), false
	}
	// Dist-tag name (e.g. next, beta).
	if tagVer, ok := meta.DistTags[requested]; ok && tagVer != "" {
		return tagVer, "analyzed dist-tag " + requested + "=" + tagVer, false
	}
	if latest == "" {
		return "", fmt.Sprintf("could not resolve range/tag %q", requested), false
	}
	return latest, fmt.Sprintf("requested range/tag %q; analyzed dist-tags.latest %s", requested, latest), true
}

func managerReason(manager, suffix string) string {
	switch strings.ToLower(manager) {
	case "pnpm":
		return "PNPM_" + suffix
	case "bun":
		return "BUN_" + suffix
	default:
		return "NPM_" + suffix
	}
}

func extractInstallSpecs(command, manager string, operations []string) []string {
	rawParts := strings.Fields(command)
	for i := range rawParts {
		rawParts[i] = unquoteToken(rawParts[i])
	}
	parts := stripCommandWrappers(rawParts)
	if len(parts) < 2 || strings.ToLower(parts[0]) != manager {
		return nil
	}

	installIdx := -1
	for i := 1; i < len(parts); i++ {
		for _, op := range operations {
			if parts[i] == op {
				installIdx = i
				break
			}
		}
		if installIdx != -1 {
			break
		}
	}
	if installIdx == -1 {
		return nil
	}

	var specs []string
	for i := installIdx + 1; i < len(parts); i++ {
		p := parts[i]
		if p == "&&" || p == ";" || p == "|" {
			break
		}
		if strings.HasPrefix(p, "-") {
			continue
		}
		// Skip leftover env assignments after the manager binary.
		if strings.Contains(p, "=") && !strings.Contains(p, "://") && !isLocalPathSpec(p) {
			continue
		}
		specs = append(specs, p)
	}
	return specs
}

// unquoteToken strips a single layer of matching single/double quotes from a token.
func unquoteToken(p string) string {
	if len(p) >= 2 {
		if (p[0] == '"' && p[len(p)-1] == '"') || (p[0] == '\'' && p[len(p)-1] == '\'') {
			return p[1 : len(p)-1]
		}
	}
	return p
}

// stripCommandWrappers removes leading sudo/env/corepack wrappers and FOO=bar
// assignments so "env FOO=1 npm install pkg" still yields package specs.
// This is intentionally not a full shell parser.
func stripCommandWrappers(parts []string) []string {
	wrappers := map[string]struct{}{
		"sudo": {}, "command": {}, "time": {}, "nice": {}, "nohup": {}, "corepack": {},
		"stdbuf": {}, "timeout": {}, "ionice": {}, "chrt": {},
	}
	// Wrappers that take a numeric or flag argument before the next command.
	argWrappers := map[string]struct{}{
		"nice": {}, "timeout": {}, "stdbuf": {}, "ionice": {}, "chrt": {},
	}
	i := 0
	for i < len(parts) {
		p := parts[i]
		lower := strings.ToLower(p)
		if _, ok := wrappers[lower]; ok {
			i++
			// `command -v` / `time -p` style: skip dashed flags.
			if (lower == "command" || lower == "time") && i < len(parts) && strings.HasPrefix(parts[i], "-") {
				i++
			}
			// nice -n 10, timeout 30s, stdbuf -oL, etc.
			if _, ok := argWrappers[lower]; ok {
				for i < len(parts) && strings.HasPrefix(parts[i], "-") {
					// flag with attached value already one token; flag + next value:
					flag := parts[i]
					i++
					if (flag == "-n" || flag == "-o" || flag == "-e" || flag == "-i" || flag == "-p") && i < len(parts) {
						i++
					}
				}
				// bare duration for timeout: timeout 30s cmd
				if lower == "timeout" && i < len(parts) && parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
					i++
				}
			}
			continue
		}
		if lower == "env" {
			i++
			for i < len(parts) {
				arg := parts[i]
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				if strings.Contains(arg, "=") {
					i++
					continue
				}
				break
			}
			continue
		}
		// Leading env assignments: FOO=1 BAR=2 npm install
		if strings.Contains(p, "=") && !strings.HasPrefix(p, "-") && !strings.Contains(p, "://") && !isLocalPathSpec(p) {
			i++
			continue
		}
		break
	}
	if i >= len(parts) {
		return nil
	}
	return parts[i:]
}

func isNonRegistryNpmSpec(spec string) bool {
	return strings.Contains(spec, "://") ||
		strings.HasPrefix(spec, "git+") ||
		strings.Contains(spec, "github.com/") ||
		strings.HasPrefix(spec, "file:") ||
		isLocalPathSpec(spec)
}

func isLocalPathSpec(spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	if strings.HasPrefix(spec, "file:") {
		return true
	}
	return strings.HasPrefix(spec, "./") ||
		strings.HasPrefix(spec, "../") ||
		strings.HasPrefix(spec, "~/") ||
		spec == "~" ||
		strings.HasPrefix(spec, "/") ||
		spec == "." ||
		spec == ".."
}

func localPackagePath(spec string) string {
	spec = strings.TrimSpace(spec)
	spec = strings.TrimPrefix(spec, "file:")
	if decoded, err := url.PathUnescape(spec); err == nil {
		spec = decoded
	}
	if spec == "" {
		return ""
	}
	if spec == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			spec = home
		}
	} else if strings.HasPrefix(spec, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			spec = filepath.Join(home, strings.TrimPrefix(spec, "~/"))
		}
	}
	return filepath.Clean(spec)
}

func normalizeNPMPackageName(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if strings.HasPrefix(spec, "npm:") {
		spec = strings.TrimPrefix(spec, "npm:")
	}
	if strings.HasPrefix(spec, "@") {
		if strings.Count(spec, "@") > 1 {
			last := strings.LastIndex(spec, "@")
			if last > 0 {
				return spec[:last]
			}
		}
		return spec
	}
	if idx := strings.Index(spec, "@"); idx > 0 {
		return spec[:idx]
	}
	return spec
}

type localPackageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

func analyzeLocalPackage(spec, manager string) []report.Finding {
	pkgPath := localPackagePath(spec)
	if pkgPath == "" {
		return nil
	}
	pkg, err := readLocalPackageJSON(pkgPath)
	if err != nil {
		return []report.Finding{{
			Severity:   report.SeverityWarning,
			Type:       manager,
			ReasonCode: managerReason(manager, "INCONCLUSIVE_LOCAL_PACKAGE"),
			Path:       spec,
			Confidence: 45,
			Evidence:   err.Error(),
		}}
	}

	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		name = spec
	}
	version := strings.TrimSpace(pkg.Version)
	if version == "" {
		version = "local"
	}

	var findings []report.Finding
	lifecycleScripts := []string{"preinstall", "install", "postinstall", "prepare"}
	foundLifecycle := false
	for _, scriptName := range lifecycleScripts {
		scriptContent, exists := pkg.Scripts[scriptName]
		if !exists {
			continue
		}
		if !foundLifecycle {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       manager,
				ReasonCode: managerReason(manager, "LIFECYCLE_SCRIPT_METADATA"),
				Path:       name + "@" + version,
				Confidence: 80,
				Evidence:   fmt.Sprintf("Local package defines %s script", scriptName),
			})
			foundLifecycle = true
		}

		body := scriptContent + "\n" + localLifecycleReferencedContent(pkgPath, scriptContent)
		// analyzeScriptBody patterns are case-insensitive; keep original body.
		contentFindings := analyzeScriptBody(
			fmt.Sprintf("%s@%s:%s", name, version, scriptName),
			body,
		)
		for i := range contentFindings {
			contentFindings[i].Type = manager
			contentFindings[i].ReasonCode = managerReason(manager, "LIFECYCLE_"+contentFindings[i].ReasonCode)
		}
		findings = append(findings, contentFindings...)
	}

	return findings
}

func readLocalPackageJSON(pkgPath string) (*localPackageJSON, error) {
	info, err := os.Stat(pkgPath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		pkgPath = filepath.Join(pkgPath, "package.json")
	}
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}
	var pkg localPackageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

func localLifecycleReferencedContent(pkgPath, script string) string {
	info, err := os.Stat(pkgPath)
	if err == nil && !info.IsDir() {
		pkgPath = filepath.Dir(pkgPath)
	}

	var out strings.Builder
	parts := strings.Fields(script)
	for i, part := range parts {
		cmd := strings.Trim(part, `"'`)
		if cmd != "node" && cmd != "bash" && cmd != "sh" {
			continue
		}
		if i+1 >= len(parts) {
			continue
		}
		rel := strings.Trim(parts[i+1], `"'`)
		if rel == "" || strings.HasPrefix(rel, "-") || filepath.IsAbs(rel) {
			continue
		}
		candidate := filepath.Clean(filepath.Join(pkgPath, rel))
		if !strings.HasPrefix(candidate, filepath.Clean(pkgPath)+string(os.PathSeparator)) {
			continue
		}
		raw, err := os.ReadFile(candidate)
		if err != nil || len(raw) > 1<<20 {
			continue
		}
		out.WriteByte('\n')
		out.Write(raw)
	}
	return out.String()
}

func fetchNPMMetadata(client *http.Client, pkg string) (*npmMetadata, error) {
	escaped := url.PathEscape(pkg)
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(npmRegistryBaseURL, "/")+"/"+escaped, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "goaudit/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("npm registry status: %d", resp.StatusCode)
	}
	var meta npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// ExtractPackageNamesFromCommand extracts normalized package names from
// a package manager install/add command string.
func ExtractPackageNamesFromCommand(command string) []string {
	type managerOps struct {
		name string
		ops  []string
	}
	managers := []managerOps{
		{"npm", []string{"install", "i"}},
		{"pnpm", []string{"add", "install", "i"}},
		{"bun", []string{"add"}},
	}
	var all []string
	seen := map[string]struct{}{}
	for _, m := range managers {
		for _, spec := range extractInstallSpecs(command, m.name, m.ops) {
			// For local paths, resolve the actual package name from package.json
			// so that require("<name>") works after npm install.
			if isLocalPathSpec(spec) {
				if name := ReadLocalPackageName(spec); name != "" {
					if _, ok := seen[name]; !ok {
						seen[name] = struct{}{}
						all = append(all, name)
					}
				}
				continue
			}
			name := normalizeNPMPackageName(spec)
			if name == "" || isNonRegistryNpmSpec(spec) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			all = append(all, name)
		}
	}
	return all
}

func HasLocalPackageInstall(command string) bool {
	type managerOps struct {
		name string
		ops  []string
	}
	managers := []managerOps{
		{"npm", []string{"install", "i"}},
		{"pnpm", []string{"add", "install", "i"}},
		{"bun", []string{"add"}},
	}
	for _, m := range managers {
		for _, spec := range extractInstallSpecs(command, m.name, m.ops) {
			if isLocalPathSpec(spec) {
				return true
			}
		}
	}
	return false
}

// RewriteSingleLocalPackageInstall rewrites a single local package install to run
// from the package directory itself. This lets the sandbox mount only that
// package instead of copying the caller's whole working directory.
func RewriteSingleLocalPackageInstall(command string) (string, string, bool) {
	type managerOps struct {
		name string
		ops  []string
	}
	managers := []managerOps{
		{"npm", []string{"install", "i"}},
		{"pnpm", []string{"add", "install", "i"}},
		{"bun", []string{"add"}},
	}
	rawParts := strings.Fields(command)
	parts := stripCommandWrappers(rawParts)
	if len(parts) < 3 {
		return "", "", false
	}
	// Preserve leading wrappers (sudo, env, FOO=bar assignments, ...) in the
	// rewritten command so sandbox execution keeps the original environment.
	prefix := ""
	if n := len(rawParts) - len(parts); n > 0 {
		prefix = strings.Join(rawParts[:n], " ") + " "
	}
	for _, m := range managers {
		if strings.ToLower(parts[0]) != m.name {
			continue
		}
		installIdx := -1
		for i := 1; i < len(parts); i++ {
			for _, op := range m.ops {
				if parts[i] == op {
					installIdx = i
					break
				}
			}
			if installIdx != -1 {
				break
			}
		}
		if installIdx == -1 {
			continue
		}
		localIdx := -1
		localCount := 0
		for i := installIdx + 1; i < len(parts); i++ {
			if parts[i] == "&&" || parts[i] == ";" || parts[i] == "|" {
				break
			}
			if strings.HasPrefix(parts[i], "-") {
				continue
			}
			if isLocalPathSpec(parts[i]) {
				localIdx = i
				localCount++
			}
		}
		if localCount != 1 {
			return "", "", false
		}
		pkgPath := localPackagePath(parts[localIdx])
		if pkgPath == "" {
			return "", "", false
		}
		absPath, err := filepath.Abs(pkgPath)
		if err != nil {
			return "", "", false
		}
		if info, err := os.Stat(absPath); err != nil || !info.IsDir() {
			return "", "", false
		}
		parts[localIdx] = "."
		return prefix + strings.Join(parts, " "), absPath, true
	}
	return "", "", false
}

// CliRegistrySpecCap returns the CLI static registry analysis cap (for tests).
func CliRegistrySpecCap() int { return cliRegistrySpecCap }

func ReadLocalPackageName(spec string) string {
	pkgPath := localPackagePath(spec)
	if pkgPath == "" {
		return ""
	}
	pkg, err := readLocalPackageJSON(pkgPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(pkg.Name)
}
