package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// cache stores per-(tool, pid, args) approval entries with an
// absolute expiry. Lookup is two operations — hit() checks + GCs;
// set() writes. Lock is a mutex, not RWMutex, because every read
// path also writes (we sweep expired entries on hit() to keep the
// map bounded).
type cache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key → expires-at (UTC)
	now     func() time.Time     // injectable for tests
}

func newCache() *cache {
	return &cache{
		entries: map[string]time.Time{},
		now:     time.Now,
	}
}

// hit returns true if key has a non-expired entry. Expired entries
// are removed on the way out (lazy GC — saves a separate sweeper
// goroutine).
func (c *cache) hit(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires, ok := c.entries[key]
	if !ok {
		return false
	}
	if c.now().After(expires) {
		delete(c.entries, key)
		return false
	}
	return true
}

// set stores key with the given TTL from now.
func (c *cache) set(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = c.now().Add(ttl)
}

// purge drops every cached approval. SECURITY D14: called after
// `policy reload` (via the broker's Invalidate method) so cached
// approvals issued under the OLD policy don't bypass the NEW
// policy's tightened rules (e.g. confirm:true newly required,
// allowed_recipients newly restricted). Simpler than diff'ing
// every cached key against the new policy — start fresh, the user
// pays at most one re-prompt per tool per TTL window.
func (c *cache) purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = map[string]time.Time{}
	return n
}

// cacheKey computes sha256 over the tool, the caller's pid,
// transport, and label, and the args. Each field is length-prefixed
// so values cannot slide into each other ("ab"+"c" is not "a"+"bc").
//
// PID stays in the key so two socket clients cannot share an
// approval. Transport and label stay in the key so a unix approval
// is not a hit for HTTP, and two HTTP labels are not a hit for
// each other. args stays in the key so a different recipient list
// is a different approval. The cache is in memory only; entries
// from before this key miss and the user is prompted again.
func cacheKey(tool string, c caller.Caller, args []byte) string {
	h := sha256.New()
	var n [8]byte
	write := func(b []byte) {
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	write([]byte(tool))
	binary.LittleEndian.PutUint64(n[:], uint64(c.PID))
	h.Write(n[:])
	write([]byte(c.Transport))
	write([]byte(c.Label))
	write(args)
	return hex.EncodeToString(h.Sum(nil))
}
