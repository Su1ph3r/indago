// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// RequestCache provides caching and deduplication for fuzz requests
type RequestCache struct {
	mu              sync.RWMutex
	baselineCache   map[string]*CachedBaseline
	requestCache    map[string]*CachedResponse
	fingerprints    map[string]bool
	maxSize         int
	ttl             time.Duration
	dedupeEnabled   bool
	baselineEnabled bool
}

// CachedBaseline represents a cached baseline response
type CachedBaseline struct {
	Response  *types.HTTPResponse
	Timestamp time.Time
	Endpoint  string
}

// CachedResponse represents a cached response for a specific request
type CachedResponse struct {
	Response  *types.HTTPResponse
	Timestamp time.Time
	HitCount  int
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	MaxSize         int           // Maximum number of cached responses
	TTL             time.Duration // Time-to-live for cache entries
	DedupeEnabled   bool          // Enable request deduplication
	BaselineEnabled bool          // Enable baseline caching
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		MaxSize:         10000,
		TTL:             30 * time.Minute,
		DedupeEnabled:   true,
		BaselineEnabled: true,
	}
}

// NewRequestCache creates a new request cache
func NewRequestCache(config *CacheConfig) *RequestCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	return &RequestCache{
		baselineCache:   make(map[string]*CachedBaseline),
		requestCache:    make(map[string]*CachedResponse),
		fingerprints:    make(map[string]bool),
		maxSize:         config.MaxSize,
		ttl:             config.TTL,
		dedupeEnabled:   config.DedupeEnabled,
		baselineEnabled: config.BaselineEnabled,
	}
}

// GetBaseline retrieves a cached baseline for an endpoint
func (c *RequestCache) GetBaseline(endpoint types.Endpoint) (*types.HTTPResponse, bool) {
	if !c.baselineEnabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.baselineKey(endpoint)
	cached, ok := c.baselineCache[key]
	if !ok {
		return nil, false
	}

	// Check TTL
	if time.Since(cached.Timestamp) > c.ttl {
		return nil, false
	}

	return cached.Response, true
}

// SetBaseline caches a baseline response
func (c *RequestCache) SetBaseline(endpoint types.Endpoint, response *types.HTTPResponse) {
	if !c.baselineEnabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.baselineKey(endpoint)
	c.baselineCache[key] = &CachedBaseline{
		Response:  response,
		Timestamp: time.Now(),
		Endpoint:  endpoint.Path,
	}
}

// IsDuplicate checks if a request has already been made
func (c *RequestCache) IsDuplicate(req payloads.FuzzRequest) bool {
	if !c.dedupeEnabled {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	fingerprint := c.requestFingerprint(req)
	return c.fingerprints[fingerprint]
}

// MarkSeen marks a request as seen
func (c *RequestCache) MarkSeen(req payloads.FuzzRequest) {
	if !c.dedupeEnabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	fingerprint := c.requestFingerprint(req)
	c.fingerprints[fingerprint] = true
}

// GetCachedResponse retrieves a cached response for a request
func (c *RequestCache) GetCachedResponse(req payloads.FuzzRequest) (*types.HTTPResponse, bool) {
	c.mu.Lock() // Use write lock since we're modifying HitCount
	defer c.mu.Unlock()

	fingerprint := c.requestFingerprint(req)
	cached, ok := c.requestCache[fingerprint]
	if !ok {
		return nil, false
	}

	// Check TTL
	if time.Since(cached.Timestamp) > c.ttl {
		return nil, false
	}

	cached.HitCount++
	return cached.Response, true
}

// CacheResponse caches a response for a request
func (c *RequestCache) CacheResponse(req payloads.FuzzRequest, response *types.HTTPResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if len(c.requestCache) >= c.maxSize {
		c.evictOldest()
	}

	fingerprint := c.requestFingerprint(req)
	c.requestCache[fingerprint] = &CachedResponse{
		Response:  response,
		Timestamp: time.Now(),
		HitCount:  0,
	}
}

// baselineKey generates a cache key for baseline lookups
func (c *RequestCache) baselineKey(endpoint types.Endpoint) string {
	return endpoint.Method + ":" + endpoint.BaseURL + endpoint.Path
}

// requestFingerprint generates a unique fingerprint for a request
func (c *RequestCache) requestFingerprint(req payloads.FuzzRequest) string {
	var parts []string

	// Include endpoint info
	parts = append(parts, req.Endpoint.Method)
	parts = append(parts, req.Endpoint.BaseURL)
	parts = append(parts, req.Endpoint.Path)

	// Include parameter info
	if req.Param != nil {
		parts = append(parts, req.Param.Name)
		parts = append(parts, req.Param.In)
	}

	// Include payload
	parts = append(parts, req.Payload.Type)
	parts = append(parts, req.Payload.Value)

	// Include position
	parts = append(parts, req.Position)

	// Generate hash
	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes
}

// evictOldest removes the oldest cache entries
func (c *RequestCache) evictOldest() {
	// Collect entries with timestamps
	type entry struct {
		key       string
		timestamp time.Time
	}

	var entries []entry
	for key, cached := range c.requestCache {
		entries = append(entries, entry{key: key, timestamp: cached.Timestamp})
	}

	// Sort by timestamp (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].timestamp.Before(entries[j].timestamp)
	})

	// Remove oldest 10%
	removeCount := len(entries) / 10
	if removeCount < 1 {
		removeCount = 1
	}

	for i := 0; i < removeCount && i < len(entries); i++ {
		delete(c.requestCache, entries[i].key)
	}
}

// Cleanup removes expired entries
func (c *RequestCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Clean baseline cache
	for key, cached := range c.baselineCache {
		if now.Sub(cached.Timestamp) > c.ttl {
			delete(c.baselineCache, key)
		}
	}

	// Clean request cache
	for key, cached := range c.requestCache {
		if now.Sub(cached.Timestamp) > c.ttl {
			delete(c.requestCache, key)
			delete(c.fingerprints, key)
		}
	}
}

// Stats returns cache statistics
func (c *RequestCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		BaselineEntries: len(c.baselineCache),
		ResponseEntries: len(c.requestCache),
		Fingerprints:    len(c.fingerprints),
	}
}

// CacheStats holds cache statistics
type CacheStats struct {
	BaselineEntries int
	ResponseEntries int
	Fingerprints    int
}

// RequestDeduplicator deduplicates a list of fuzz requests
type RequestDeduplicator struct {
	seen map[string]bool
}

// NewRequestDeduplicator creates a new deduplicator
func NewRequestDeduplicator() *RequestDeduplicator {
	return &RequestDeduplicator{
		seen: make(map[string]bool),
	}
}

// Deduplicate removes duplicate requests from a list
func (d *RequestDeduplicator) Deduplicate(requests []payloads.FuzzRequest) []payloads.FuzzRequest {
	var unique []payloads.FuzzRequest

	for _, req := range requests {
		fingerprint := d.fingerprint(req)
		if !d.seen[fingerprint] {
			d.seen[fingerprint] = true
			unique = append(unique, req)
		}
	}

	return unique
}

// fingerprint generates a fingerprint for deduplication
func (d *RequestDeduplicator) fingerprint(req payloads.FuzzRequest) string {
	var parts []string

	parts = append(parts, req.Endpoint.Method)
	parts = append(parts, req.Endpoint.Path)

	if req.Param != nil {
		parts = append(parts, req.Param.Name)
	}

	parts = append(parts, req.Payload.Type)
	parts = append(parts, req.Payload.Value)

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// RemovedCount returns the number of duplicates removed
func (d *RequestDeduplicator) RemovedCount(originalCount int) int {
	return originalCount - len(d.seen)
}
