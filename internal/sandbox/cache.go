package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"
)

// DefaultCacheSubdir is the default directory for sandbox cache metadata.
const DefaultCacheSubdir = ".goaudit/cache"

// CacheDirEnvVar allows overriding cache directory without CLI flags.
const CacheDirEnvVar = "GOAUDIT_CACHE_DIR"

// CacheRefreshAfter is the age after which :latest images must be revalidated.
const CacheRefreshAfter = 5 * 24 * time.Hour // 5 days

// CacheVersion tracks the cache file format version.
const CacheVersion = 1

// CachedContainer holds metadata about a cached sandbox container.
type CachedContainer struct {
	ContainerID string    `json:"container_id"`
	Image       string    `json:"image"`
	Runtime     string    `json:"runtime"`
	Profile     string    `json:"profile"`
	RunAsRoot   bool      `json:"run_as_root"`
	Network     bool      `json:"network_enabled"`
	ImageDigest string    `json:"image_digest"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

// CacheData is the on-disk cache format.
type CacheData struct {
	Version    int                         `json:"version"`
	Containers map[string]*CachedContainer `json:"containers"`
}

// CacheManager manages cached sandbox containers.
type CacheManager struct {
	mu       sync.Mutex
	dir      string
	filePath string
	lockPath string
	data     *CacheData
	cli      *client.Client
}

// NewCacheManager creates a CacheManager rooted at the given directory.
// If dir is empty, it defaults to ~/.goaudit/cache.
func NewCacheManager(dir string) (*CacheManager, error) {
	resolved, err := ResolveCacheDir(dir)
	if err != nil {
		return nil, err
	}
	dir = resolved

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}

	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "cache.json"),
		lockPath: filepath.Join(dir, "cache.lock"),
		cli:      cli,
	}

	if err := cm.load(); err != nil {
		// If load fails, start with empty cache.
		cm.data = &CacheData{Version: CacheVersion, Containers: map[string]*CachedContainer{}}
	}

	return cm, nil
}

// ResolveCacheDir resolves cache directory with precedence:
// explicit argument > GOAUDIT_CACHE_DIR > ~/.goaudit/cache.
func ResolveCacheDir(dir string) (string, error) {
	if strings.TrimSpace(dir) != "" {
		return dir, nil
	}
	if envDir := strings.TrimSpace(os.Getenv(CacheDirEnvVar)); envDir != "" {
		return envDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, DefaultCacheSubdir), nil
}

// cacheKey builds the map key for runtime/profile plus execution policy.
func cacheKey(runtime, profile string, runAsRoot, networkEnabled bool) string {
	rt := runtime
	if rt == "" {
		rt = "runc"
	}
	return fmt.Sprintf("%s:%s:root=%t:net=%t", rt, profile, runAsRoot, networkEnabled)
}

// Lookup finds a valid cached container for the given runtime, profile, and policy.
// Returns nil if no valid entry exists.
func (cm *CacheManager) Lookup(ctx context.Context, runtime, profile string, runAsRoot, networkEnabled bool) *CachedContainer {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return nil
	}
	defer cm.unlock(lf)

	if err := cm.reloadLocked(); err != nil {
		return nil
	}

	key := cacheKey(runtime, profile, runAsRoot, networkEnabled)
	entry, ok := cm.data.Containers[key]
	if !ok {
		return nil
	}

	// Check container still exists.
	if !cm.containerExists(ctx, entry.ContainerID) {
		delete(cm.data.Containers, key)
		_ = cm.saveLocked()
		return nil
	}

	return entry
}

// Store saves a cache entry for the given runtime, profile, and policy.
func (cm *CacheManager) Store(ctx context.Context, runtime, profile string, runAsRoot, networkEnabled bool, containerID, img, digest string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return err
	}
	defer cm.unlock(lf)

	if err := cm.reloadLocked(); err != nil {
		return err
	}

	key := cacheKey(runtime, profile, runAsRoot, networkEnabled)

	// If there's an existing entry with a different container, remove the old one.
	if old, ok := cm.data.Containers[key]; ok && old.ContainerID != containerID {
		_ = cm.stopAndRemoveContainer(ctx, old.ContainerID)
	}

	now := time.Now()
	cm.data.Containers[key] = &CachedContainer{
		ContainerID: containerID,
		Image:       img,
		Runtime:     runtime,
		Profile:     profile,
		RunAsRoot:   runAsRoot,
		Network:     networkEnabled,
		ImageDigest: digest,
		CreatedAt:   now,
		LastUsed:    now,
	}

	return cm.saveLocked()
}

// TouchLastUsed updates the last-used timestamp for a cache entry.
func (cm *CacheManager) TouchLastUsed(runtime, profile string, runAsRoot, networkEnabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return
	}
	defer cm.unlock(lf)

	_ = cm.reloadLocked()

	key := cacheKey(runtime, profile, runAsRoot, networkEnabled)
	if entry, ok := cm.data.Containers[key]; ok {
		entry.LastUsed = time.Now()
		_ = cm.saveLocked()
	}
}

// Invalidate removes a specific cache entry and its container.
func (cm *CacheManager) Invalidate(ctx context.Context, runtime, profile string, runAsRoot, networkEnabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return
	}
	defer cm.unlock(lf)

	if err := cm.reloadLocked(); err != nil {
		return
	}
	key := cacheKey(runtime, profile, runAsRoot, networkEnabled)
	cm.removeEntryLocked(ctx, key)
}

// InvalidateAll removes all cached containers.
func (cm *CacheManager) InvalidateAll(ctx context.Context) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return
	}
	defer cm.unlock(lf)

	_ = cm.reloadLocked()
	for key := range cm.data.Containers {
		cm.removeEntryLocked(ctx, key)
	}
	_ = os.Remove(cm.filePath)
	_ = os.Remove(cm.lockPath)
	cm.data = &CacheData{Version: CacheVersion, Containers: map[string]*CachedContainer{}}
}

// InvalidateByRuntime removes all cached containers for a specific runtime.
func (cm *CacheManager) InvalidateByRuntime(ctx context.Context, runtime string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return
	}
	defer cm.unlock(lf)

	if err := cm.reloadLocked(); err != nil {
		return
	}
	for key, entry := range cm.data.Containers {
		entryRT := entry.Runtime
		if entryRT == "" {
			entryRT = "runc"
		}
		targetRT := runtime
		if targetRT == "" {
			targetRT = "runc"
		}
		if entryRT == targetRT {
			cm.removeEntryLocked(ctx, key)
		}
	}
}

// Entries returns a copy of all cache entries (for status display).
func (cm *CacheManager) Entries() map[string]*CachedContainer {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	lf, err := cm.lock()
	if err != nil {
		return map[string]*CachedContainer{}
	}
	defer cm.unlock(lf)

	if err := cm.reloadLocked(); err != nil {
		return map[string]*CachedContainer{}
	}
	result := make(map[string]*CachedContainer, len(cm.data.Containers))
	for k, v := range cm.data.Containers {
		cp := *v
		result[k] = &cp
	}
	return result
}

// Dir returns the cache directory path used by this manager.
func (cm *CacheManager) Dir() string {
	return cm.dir
}

// LocalImageDigest returns the digest (RepoDigests) of a locally available image.
func (cm *CacheManager) LocalImageDigest(ctx context.Context, img string) string {
	inspect, _, err := cm.cli.ImageInspectWithRaw(ctx, img)
	if err != nil {
		return ""
	}
	if len(inspect.RepoDigests) > 0 {
		return inspect.RepoDigests[0]
	}
	return inspect.ID
}

// ImageChanged checks whether the local image digest differs from the cached digest.
func (cm *CacheManager) ImageChanged(ctx context.Context, img, cachedDigest string) bool {
	current := cm.LocalImageDigest(ctx, img)
	if current == "" || cachedDigest == "" {
		return true
	}
	return current != cachedDigest
}

// ShouldRefreshLatest reports whether a cached entry should be refreshed.
// Returns:
//   - refresh: true when cache should be invalidated and rebuilt
//   - offline: true when refresh is required but remote digest couldn't be checked
func (cm *CacheManager) ShouldRefreshLatest(ctx context.Context, entry *CachedContainer) (refresh bool, offline bool) {
	if entry == nil {
		return true, false
	}
	if time.Since(entry.CreatedAt) < CacheRefreshAfter {
		return false, false
	}
	if !strings.HasSuffix(entry.Image, ":latest") {
		return false, false
	}

	remoteDigest, err := cm.RemoteDigest(ctx, entry.Image)
	if err != nil || remoteDigest == "" {
		return true, true
	}
	localDigest := entry.ImageDigest
	if localDigest == "" {
		localDigest = cm.LocalImageDigest(ctx, entry.Image)
	}
	if localDigest == "" {
		return true, false
	}
	return remoteDigest != localDigest, false
}

// RemoteDigest returns the remote registry digest for an image tag.
func (cm *CacheManager) RemoteDigest(ctx context.Context, img string) (string, error) {
	inspect, err := cm.cli.DistributionInspect(ctx, img, "")
	if err != nil {
		return "", err
	}
	d := inspect.Descriptor.Digest.String()
	if d == "" {
		return "", fmt.Errorf("empty remote digest for %s", img)
	}
	return d, nil
}

// Close closes the underlying Docker client.
func (cm *CacheManager) Close() {
	if cm.cli != nil {
		cm.cli.Close()
	}
}

// --- internal helpers ---

func (cm *CacheManager) load() error {
	return cm.reloadLocked()
}

func (cm *CacheManager) saveLocked() error {
	if cm.filePath == "" || cm.dir == "" {
		return nil
	}
	if err := os.MkdirAll(cm.dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cm.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := cm.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, cm.filePath)
}

func (cm *CacheManager) removeEntryLocked(ctx context.Context, key string) {
	entry, ok := cm.data.Containers[key]
	if !ok {
		return
	}
	_ = cm.stopAndRemoveContainer(ctx, entry.ContainerID)
	delete(cm.data.Containers, key)
	_ = cm.saveLocked()
}

func (cm *CacheManager) containerExists(ctx context.Context, containerID string) bool {
	_, err := cm.cli.ContainerInspect(ctx, containerID)
	return err == nil
}

func (cm *CacheManager) stopAndRemoveContainer(ctx context.Context, containerID string) error {
	timeout := 5
	_ = cm.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	return cm.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
}

// PullAndDigest pulls an image and returns its local digest.
func (cm *CacheManager) PullAndDigest(ctx context.Context, img string) (string, error) {
	reader, err := cm.cli.ImagePull(ctx, img, image.PullOptions{})
	if err != nil {
		return "", err
	}
	defer reader.Close()
	// Drain the pull output.
	buf := make([]byte, 4096)
	for {
		_, readErr := reader.Read(buf)
		if readErr != nil {
			break
		}
	}
	digest := cm.LocalImageDigest(ctx, img)
	return digest, nil
}

func (cm *CacheManager) reloadLocked() error {
	if cm.filePath == "" {
		if cm.data == nil {
			cm.data = &CacheData{Version: CacheVersion, Containers: map[string]*CachedContainer{}}
		}
		return nil
	}
	if err := os.MkdirAll(cm.dir, 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			cm.data = &CacheData{Version: CacheVersion, Containers: map[string]*CachedContainer{}}
			return nil
		}
		return err
	}
	var cd CacheData
	if err := json.Unmarshal(data, &cd); err != nil {
		return err
	}
	if cd.Version != CacheVersion {
		return fmt.Errorf("unsupported cache version %d", cd.Version)
	}
	if cd.Containers == nil {
		cd.Containers = map[string]*CachedContainer{}
	}
	cm.data = &cd
	return nil
}

func (cm *CacheManager) lock() (*os.File, error) {
	if cm.lockPath == "" || cm.dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(cm.dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(cm.lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (cm *CacheManager) unlock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}
