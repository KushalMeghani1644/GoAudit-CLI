package sandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/client"
)

func TestCacheKey(t *testing.T) {
	tests := []struct {
		runtime, profile string
		net              bool
		want             string
	}{
		{"runsc", "npm", true, "runsc:npm:net=true"},
		{"", "npm", false, "runc:npm:net=false"},
		{"runsc", "pnpm", true, "runsc:pnpm:net=true"},
	}
	for _, tt := range tests {
		got := cacheKey(tt.runtime, tt.profile, tt.net)
		if got != tt.want {
			t.Errorf("cacheKey(%q, %q, %t) = %q, want %q", tt.runtime, tt.profile, tt.net, got, tt.want)
		}
	}
}

func TestNetworkModeMatchesPolicy(t *testing.T) {
	tests := []struct {
		mode   string
		net    bool
		wantOK bool
	}{
		// Offline cache key requires NetworkMode none.
		{"none", false, true},
		{"bridge", false, false},
		{"", false, false},
		{"default", false, false},
		// Online cache key accepts any non-none mode (including Docker default).
		{"none", true, false},
		{"bridge", true, true},
		{"", true, true},
		{"default", true, true},
		{"goaudit-net", true, true},
	}
	for _, tt := range tests {
		got := networkModeMatchesPolicy(tt.mode, tt.net)
		if got != tt.wantOK {
			t.Errorf("networkModeMatchesPolicy(%q, %t) = %t, want %t", tt.mode, tt.net, got, tt.wantOK)
		}
	}
}

func TestCacheDataLoadSave(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache.json")

	// Write valid cache data.
	data := CacheData{
		Version: CacheVersion,
		Containers: map[string]*CachedContainer{
			"runsc:npm:net=true": {
				ContainerID: "abc123",
				Image:       "ghcr.io/test/image:latest",
				Runtime:     "runsc",
				Profile:     "npm",
				Network:     true,
				ImageDigest: "sha256:deadbeef",
				CreatedAt:   time.Now().Add(-1 * time.Hour),
				LastUsed:    time.Now(),
			},
		},
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Load it back via a CacheManager (with nil Docker client since we're unit testing).
	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	if err := cm.load(); err != nil {
		t.Fatalf("load() failed: %v", err)
	}

	if cm.data.Version != CacheVersion {
		t.Errorf("version = %d, want %d", cm.data.Version, CacheVersion)
	}
	entry, ok := cm.data.Containers["runsc:npm:net=true"]
	if !ok {
		t.Fatal("expected runsc:npm entry")
	}
	if entry.ContainerID != "abc123" {
		t.Errorf("containerID = %q, want %q", entry.ContainerID, "abc123")
	}
	if entry.Image != "ghcr.io/test/image:latest" {
		t.Errorf("image = %q, want %q", entry.Image, "ghcr.io/test/image:latest")
	}

	// Test save.
	cm.data.Containers["runc:npm:net=false"] = &CachedContainer{
		ContainerID: "def456",
		Image:       "node:current-slim",
		Runtime:     "",
		Profile:     "npm",
		ImageDigest: "sha256:cafebabe",
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
	}
	if err := cm.saveLocked(); err != nil {
		t.Fatalf("saveLocked() failed: %v", err)
	}

	// Reload and verify.
	cm2 := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	if err := cm2.load(); err != nil {
		t.Fatalf("second load() failed: %v", err)
	}
	if len(cm2.data.Containers) != 2 {
		t.Errorf("expected 2 entries, got %d", len(cm2.data.Containers))
	}
	if _, ok := cm2.data.Containers["runc:npm:net=false"]; !ok {
		t.Fatal("expected runc:npm entry after save+reload")
	}
}

func TestTakeAtomicallyRemovesSingleUseContainer(t *testing.T) {
	var inspectRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/containers/abc123/json") {
			inspectRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"abc123","State":{"Running":false},"HostConfig":{"NetworkMode":"bridge"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	dockerClient, err := client.NewClientWithOpts(
		client.WithHost(server.URL),
		client.WithHTTPClient(server.Client()),
		client.WithVersion("1.44"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dockerClient.Close()

	dir := t.TempDir()
	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "cache.json"),
		lockPath: filepath.Join(dir, "cache.lock"),
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				"runsc:npm:net=true": {
					ContainerID: "abc123",
					Runtime:     "runsc",
					Profile:     "npm",
					Network:     true,
					SingleUse:   true,
				},
			},
		},
		cli: dockerClient,
	}
	if err := cm.saveLocked(); err != nil {
		t.Fatal(err)
	}

	entry := cm.Take(context.Background(), "runsc", "npm", true)
	if entry == nil || entry.ContainerID != "abc123" {
		t.Fatalf("Take() = %#v, want container abc123", entry)
	}

	// A second manager models another process. The persisted claim must prevent
	// it from receiving the same mutable container.
	cm2 := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "cache.json"),
		lockPath: filepath.Join(dir, "cache.lock"),
		cli:      dockerClient,
	}
	if second := cm2.Take(context.Background(), "runsc", "npm", true); second != nil {
		t.Fatalf("second Take() = %#v, want nil", second)
	}
	if inspectRequests != 2 {
		t.Fatalf("inspect requests = %d, want 2 for existence and network validation", inspectRequests)
	}

	// Entries written by older versions were reusable and may already contain
	// target mutations. They must be discarded without ever being inspected for use.
	cm.data.Containers["runsc:npm:net=true"] = &CachedContainer{
		ContainerID: "legacy",
		Runtime:     "runsc",
		Profile:     "npm",
		Network:     true,
		SingleUse:   false,
	}
	if err := cm.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if legacy := cm.Take(context.Background(), "runsc", "npm", true); legacy != nil {
		t.Fatalf("Take() returned reusable legacy entry: %#v", legacy)
	}
	if entries := cm.Entries(); len(entries) != 0 {
		t.Fatalf("legacy cache entry was not removed: %#v", entries)
	}
	if inspectRequests != 2 {
		t.Fatal("legacy cache entry was inspected for reuse")
	}
}

func TestStorePreservesExistingEntryWhenRemovalFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/old/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/containers/old") {
			http.Error(w, "removal failed", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	dockerClient, err := client.NewClientWithOpts(
		client.WithHost(server.URL),
		client.WithHTTPClient(server.Client()),
		client.WithVersion("1.44"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dockerClient.Close()

	dir := t.TempDir()
	key := cacheKey("runsc", "npm", true)
	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "cache.json"),
		lockPath: filepath.Join(dir, "cache.lock"),
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				key: {
					ContainerID: "old",
					Runtime:     "runsc",
					Profile:     "npm",
					Network:     true,
					SingleUse:   true,
				},
			},
		},
		cli: dockerClient,
	}
	if err := cm.saveLocked(); err != nil {
		t.Fatal(err)
	}

	err = cm.Store(context.Background(), "runsc", "npm", true, "new", "image", "digest")
	if err == nil {
		t.Fatal("Store() succeeded despite failure to remove the previous container")
	}
	if entry := cm.Entries()[key]; entry == nil || entry.ContainerID != "old" {
		t.Fatalf("cached entry = %#v, want previous container old", entry)
	}
}

func TestCacheLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "nonexistent.json"),
	}
	err := cm.load()
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
}

func TestCacheLoadInvalidVersion(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache.json")

	data := CacheData{
		Version:    999,
		Containers: map[string]*CachedContainer{},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(filePath, raw, 0o644)

	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	err := cm.load()
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestCacheSaveCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	filePath := filepath.Join(dir, "cache.json")

	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
		data: &CacheData{
			Version:    CacheVersion,
			Containers: map[string]*CachedContainer{},
		},
	}

	if err := cm.saveLocked(); err != nil {
		t.Fatalf("saveLocked() failed: %v", err)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("expected cache file to exist")
	}
}

func TestEntries(t *testing.T) {
	cm := &CacheManager{
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				"runsc:npm:net=false": {ContainerID: "abc", Profile: "npm"},
				"runc:bun:net=false":  {ContainerID: "def", Profile: "bun"},
			},
		},
	}

	entries := cm.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Verify it's a copy (modifying shouldn't affect original).
	entries["runsc:npm:net=false"].ContainerID = "modified"
	if cm.data.Containers["runsc:npm:net=false"].ContainerID == "modified" {
		t.Fatal("Entries() should return a copy, not a reference")
	}
}

func TestResolveCacheDirFromEnv(t *testing.T) {
	t.Setenv(CacheDirEnvVar, "/tmp/goaudit-cache-env")
	got, err := ResolveCacheDir("")
	if err != nil {
		t.Fatalf("ResolveCacheDir returned error: %v", err)
	}
	if got != "/tmp/goaudit-cache-env" {
		t.Fatalf("expected env cache dir, got %q", got)
	}
}

func TestResolveCacheDirDefault(t *testing.T) {
	t.Setenv(CacheDirEnvVar, "")
	got, err := ResolveCacheDir("")
	if err != nil {
		t.Fatalf("ResolveCacheDir returned error: %v", err)
	}
	if !strings.HasSuffix(got, filepath.FromSlash(".goaudit/cache")) {
		t.Fatalf("expected default cache suffix, got %q", got)
	}
}

func TestTouchLastUsed(t *testing.T) {
	cm := &CacheManager{
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				"runsc:npm:net=true": {
					ContainerID: "abc",
					Profile:     "npm",
					Runtime:     "runsc",
					Network:     true,
					LastUsed:    time.Now().Add(-24 * time.Hour),
				},
			},
		},
	}

	before := cm.data.Containers["runsc:npm:net=true"].LastUsed
	cm.TouchLastUsed("runsc", "npm", true)
	after := cm.data.Containers["runsc:npm:net=true"].LastUsed

	if !after.After(before) {
		t.Error("TouchLastUsed should update LastUsed to a later time")
	}
}
