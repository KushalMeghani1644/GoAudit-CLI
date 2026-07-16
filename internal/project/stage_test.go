package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageForSandboxMinimalExcludesSecrets(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":3}`)
	mustWrite(t, filepath.Join(root, ".env"), `SECRET=real`)
	mustWrite(t, filepath.Join(root, ".npmrc"), `//registry.npmjs.org/:_authToken=real-token`)
	mustWrite(t, filepath.Join(root, "src", "index.js"), `console.log(1)`)
	mustWrite(t, filepath.Join(root, "patches", "foo.patch"), `diff`)

	stage, err := StageForSandbox(root, StageOptions{FullTree: false})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()

	if !fileExists(filepath.Join(stage.Dir, "package.json")) {
		t.Fatal("expected package.json in stage")
	}
	if !fileExists(filepath.Join(stage.Dir, "package-lock.json")) {
		t.Fatal("expected package-lock.json in stage")
	}
	if !fileExists(filepath.Join(stage.Dir, "patches", "foo.patch")) {
		t.Fatal("expected patches in minimal stage")
	}
	if fileExists(filepath.Join(stage.Dir, ".env")) {
		t.Fatal("minimal stage must not include .env")
	}
	if fileExists(filepath.Join(stage.Dir, ".npmrc")) {
		t.Fatal("minimal stage must not include .npmrc")
	}
	if fileExists(filepath.Join(stage.Dir, "src", "index.js")) {
		t.Fatal("minimal stage must not include full source tree")
	}
}

func TestStageForSandboxFullTreeRedactsSecrets(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	mustWrite(t, filepath.Join(root, "src", "index.js"), `console.log(1)`)
	mustWrite(t, filepath.Join(root, ".env"), `SECRET=real`)
	mustWrite(t, filepath.Join(root, ".env.local"), `SECRET=real`)
	mustWrite(t, filepath.Join(root, "certs", "server.pem"), `PEM`)
	mustWrite(t, filepath.Join(root, ".ssh", "id_rsa"), `KEY`)
	mustWrite(t, filepath.Join(root, ".aws", "credentials"), `aws`)
	mustWrite(t, filepath.Join(root, ".npmrc"), `token=x`)
	_ = os.MkdirAll(filepath.Join(root, "node_modules", "lodash"), 0o755)
	mustWrite(t, filepath.Join(root, "node_modules", "lodash", "index.js"), `module.exports=1`)
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	mustWrite(t, filepath.Join(root, ".git", "config"), `git`)

	stage, err := StageForSandbox(root, StageOptions{FullTree: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()

	if !fileExists(filepath.Join(stage.Dir, "package.json")) {
		t.Fatal("expected package.json")
	}
	if !fileExists(filepath.Join(stage.Dir, "src", "index.js")) {
		t.Fatal("expected source in full tree stage")
	}
	for _, bad := range []string{
		".env",
		".env.local",
		filepath.Join("certs", "server.pem"),
		filepath.Join(".ssh", "id_rsa"),
		filepath.Join(".aws", "credentials"),
		".npmrc",
		filepath.Join("node_modules", "lodash", "index.js"),
		filepath.Join(".git", "config"),
	} {
		if fileExists(filepath.Join(stage.Dir, bad)) {
			t.Fatalf("full tree stage must not include secret/excluded path %s", bad)
		}
	}
}

func TestIsSecretPath(t *testing.T) {
	cases := []struct {
		rel, base string
		want      bool
	}{
		{".env", ".env", true},
		{".env.production", ".env.production", true},
		{"src/index.js", "index.js", false},
		{".ssh/id_rsa", "id_rsa", true},
		{".aws/credentials", "credentials", true},
		{"certs/server.pem", "server.pem", true},
		{"readme.md", "readme.md", false},
	}
	for _, tt := range cases {
		if got := isSecretPath(tt.rel, tt.base); got != tt.want {
			t.Errorf("isSecretPath(%q, %q) = %v, want %v", tt.rel, tt.base, got, tt.want)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
