package project

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestListDirectDeps(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"lodash": "^4.0.0"},
		"devDependencies": {"typescript": "^5.0.0"},
		"optionalDependencies": {"fsevents": "^2.0.0"}
	}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}

	deps := proj.ListDirectDeps()
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %#v", len(deps), deps)
	}

	specs := proj.ListDirectDepSpecs()
	if len(specs) != 3 {
		t.Fatalf("expected 3 dep specs, got %#v", specs)
	}
	found := false
	for _, s := range specs {
		if s.Name == "lodash" && s.Version == "^4.0.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected lodash@^4.0.0 in specs, got %#v", specs)
	}
}

func TestListTransitiveFromPackageLock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"lodash":"^4.0.0"}}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"packages": {
			"": {"name": "demo"},
			"node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
			"node_modules/@types/node": {"name": "@types/node", "version": "20.0.0"}
		}
	}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}

	transitive, err := proj.ListTransitiveDeps()
	if err != nil {
		t.Fatal(err)
	}
	if len(transitive) != 2 {
		t.Fatalf("expected 2 transitive deps, got %#v", transitive)
	}

	all, err := proj.ListDepsForStatic(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected merged deps, got %#v", all)
	}
	// Prefer resolved lock versions.
	joined := strings.Join(all, ",")
	if !strings.Contains(joined, "lodash@4.17.21") {
		t.Fatalf("expected resolved lodash version in static deps, got %#v", all)
	}
}

func TestListTransitiveFromPnpmLock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"lodash":"^4.0.0"}}`)
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-test}
  '@types/node@20.0.0':
    resolution: {integrity: sha512-test}
`)

	proj, err := Open(root, "pnpm")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) < 2 {
		t.Fatalf("expected pnpm lock packages, got %#v", specs)
	}
	foundLodash := false
	for _, s := range specs {
		if s.Name == "lodash" && s.Version == "4.17.21" {
			foundLodash = true
		}
	}
	if !foundLodash {
		t.Fatalf("expected lodash@4.17.21 from pnpm lock, got %#v", specs)
	}
}

func TestLockParsersKeepDistinctPackageVersions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"packages": {
			"node_modules/a": {"name": "a", "version": "1.0.0"},
			"node_modules/b/node_modules/a": {"name": "a", "version": "2.0.0"}
		}
	}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0] != (DepSpec{Name: "a", Version: "1.0.0"}) || specs[1] != (DepSpec{Name: "a", Version: "2.0.0"}) {
		t.Fatalf("expected both resolved versions in name/version order, got %#v", specs)
	}

	staticSpecs, err := proj.ListDepSpecsForStatic(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(staticSpecs) != 2 || staticSpecs[0] != (DepSpec{Name: "a", Version: "1.0.0"}) || staticSpecs[1] != (DepSpec{Name: "a", Version: "2.0.0"}) {
		t.Fatalf("expected both resolved versions in static deps, got %#v", staticSpecs)
	}
}

func TestListTransitiveFromLegacyPackageLockIncludesNestedDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 1,
		"dependencies": {
			"parent": {
				"version": "1.0.0",
				"dependencies": {
					"child": {"version": "2.0.0"}
				}
			}
		}
	}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	want := []DepSpec{{Name: "child", Version: "2.0.0"}, {Name: "parent", Version: "1.0.0"}}
	if len(specs) != len(want) || specs[0] != want[0] || specs[1] != want[1] {
		t.Fatalf("expected nested legacy lock deps %#v, got %#v", want, specs)
	}
}

func TestTransitiveLockfileUsesSelectedManager(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"packages": {"node_modules/stale": {"name": "stale", "version": "1.0.0"}}
	}`)
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'

packages:
  current@2.0.0:
    resolution: {integrity: sha512-test}
`)

	proj, err := Open(root, ManagerPNPM)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0] != (DepSpec{Name: "current", Version: "2.0.0"}) {
		t.Fatalf("expected pnpm lock deps, got %#v", specs)
	}
	found, kind := proj.TransitiveLockfileStatus()
	if !found || kind != "pnpm-lock.yaml" {
		t.Fatalf("expected pnpm lockfile status, got %v %q", found, kind)
	}
}

func TestPnpmLockSkipsAliases(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'

packages:
  foo@npm:bar@1.0.0:
    resolution: {integrity: sha512-test}
  valid@2.0.0:
    resolution: {integrity: sha512-test}
`)

	proj, err := Open(root, "pnpm")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0] != (DepSpec{Name: "valid", Version: "2.0.0"}) {
		t.Fatalf("expected alias to be skipped, got %#v", specs)
	}
}

func TestBunLockParsesJSONC(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo"}`)
	writeFile(t, filepath.Join(root, "bun.lock"), `{
  // Bun lockfiles allow comments and trailing commas.
  "packages": {
    "lodash": ["lodash@4.17.21",], /* resolved package */
  },
}`)

	proj, err := Open(root, "bun")
	if err != nil {
		t.Fatal(err)
	}
	specs, err := proj.ListTransitiveDepSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0] != (DepSpec{Name: "lodash", Version: "4.17.21"}) {
		t.Fatalf("expected JSONC bun lock to parse, got %#v", specs)
	}
}

func TestWorkspaceDirectDeps(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"private": true,
		"workspaces": ["packages/*"],
		"dependencies": {"root-only": "1.0.0"}
	}`)
	writeFile(t, filepath.Join(root, "packages", "a", "package.json"), `{
		"name": "a",
		"dependencies": {"workspace-dep": "2.0.0"}
	}`)

	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	names := proj.ListDirectDeps()
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "root-only") || !strings.Contains(joined, "workspace-dep") {
		t.Fatalf("expected workspace deps merged, got %#v", names)
	}
}

func TestTransitiveLockfileStatus(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"x"}`)
	proj, err := Open(root, "")
	if err != nil {
		t.Fatal(err)
	}
	found, kind := proj.TransitiveLockfileStatus()
	if found || kind != "" {
		t.Fatalf("expected no lockfile, got %v %q", found, kind)
	}
}
