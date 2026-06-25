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
	cliRegistrySpecCap  = 3
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

	if cap > 0 && len(specs) > cap {
		specs = specs[:cap]
	}

	client := &http.Client{Timeout: 8 * time.Second}
	jobs := make(chan string)
	var (
		mu       sync.Mutex
		findings []report.Finding
		wg       sync.WaitGroup
		jobSeq   atomic.Uint64
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

	pkg := normalizeNPMPackageName(spec)
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

	latest := meta.DistTags["latest"]
	if latest != "" {
		if version, ok := meta.Versions[latest]; ok {
			lifecycleScripts := []string{"preinstall", "install", "postinstall", "prepare"}
			foundLifecycle := false
			for _, scriptName := range lifecycleScripts {
				scriptContent, exists := version.Scripts[scriptName]
				if !exists {
					continue
				}
				if !foundLifecycle {
					findings = append(findings, report.Finding{
						Severity:   report.SeverityWarning,
						Type:       manager,
						ReasonCode: managerReason(manager, "LIFECYCLE_SCRIPT_METADATA"),
						Path:       pkg + "@" + latest,
						Confidence: 80,
						Evidence:   fmt.Sprintf("Latest package version defines %s script", scriptName),
					})
					foundLifecycle = true
				}
				// Analyze the actual content of the lifecycle script for dangerous patterns.
				contentFindings := analyzeScriptBody(
					fmt.Sprintf("%s@%s:%s", pkg, latest, scriptName),
					strings.ToLower(scriptContent),
				)
				for i := range contentFindings {
					contentFindings[i].Type = manager
					contentFindings[i].ReasonCode = managerReason(manager, "LIFECYCLE_"+contentFindings[i].ReasonCode)
				}
				findings = append(findings, contentFindings...)
			}
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
	parts := strings.Fields(command)
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
		specs = append(specs, p)
	}
	return specs
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
		contentFindings := analyzeScriptBody(
			fmt.Sprintf("%s@%s:%s", name, version, scriptName),
			strings.ToLower(body),
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
	parts := strings.Fields(command)
	if len(parts) < 3 {
		return "", "", false
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
		return strings.Join(parts, " "), absPath, true
	}
	return "", "", false
}

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
