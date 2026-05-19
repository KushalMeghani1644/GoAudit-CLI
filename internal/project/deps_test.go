package project

import (
	"path/filepath"
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
}

func TestListTransitiveFromPackageLock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"lodash":"^4.0.0"}}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"packages": {
			"": {"name": "demo"},
			"node_modules/lodash": {"name": "lodash"},
			"node_modules/@types/node": {"name": "@types/node"}
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
}
