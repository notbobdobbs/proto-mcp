package httpmcp

import (
	"context"
	"errors"
	"sync"
	"time"
)

// errCooldown is returned when a declined remote-unlock prompt is
// still inside the 60s cooldown. The helper is not started again.
var errCooldown = errors.New("the remote unlock prompt was not approved; wait a minute before trying again")

// UnlockClock is the wall-clock limit for the HTTP door. Idle bumps
// do not move it. A Unix caller does not read it.
type UnlockClock struct {
	mu       sync.Mutex
	at       time.Time
	declined time.Time
	now      func() time.Time
	cooldown time.Duration
	onStamp  func()
}

func NewUnlockClock(now func() time.Time) *UnlockClock {
	if now == nil {
		now = time.Now
	}
	return &UnlockClock{now: now, cooldown: 60 * time.Second}
}

// SetOnStamp registers a callback for a successful stamp. It runs
// after the clock lock is released.
func (c *UnlockClock) SetOnStamp(fn func()) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onStamp = fn
	c.mu.Unlock()
}

// Unix is the stamp as seconds, or 0 when nothing has been stamped.
func (c *UnlockClock) Unix() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return 0
	}
	return c.at.Unix()
}

// Stamp records a successful Touch ID that unlocks the session.
func (c *UnlockClock) Stamp(t time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.at = t
	c.declined = time.Time{}
	fn := c.onStamp
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// Age is the time since the last stamp. A zero stamp is a large age.
func (c *UnlockClock) Age(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return 1<<63 - 1
	}
	return now.Sub(c.at)
}

// Gate prompts when the stamp is older than hours. Approval resets
// the stamp. Decline leaves the stamp unchanged and starts the same
// 60s cooldown as a refused unlock. hours <= 0 means 8.
func (c *UnlockClock) Gate(ctx context.Context, hours int, prompt func(context.Context) error) error {
	if hours <= 0 {
		hours = 8
	}
	now := c.now()
	c.mu.Lock()
	if !c.declined.IsZero() && now.Sub(c.declined) < c.cooldown {
		c.mu.Unlock()
		return errCooldown
	}
	due := c.at.IsZero() || now.Sub(c.at) > time.Duration(hours)*time.Hour
	c.mu.Unlock()
	if !due {
		return nil
	}
	if err := prompt(ctx); err != nil {
		c.mu.Lock()
		c.declined = c.now()
		c.mu.Unlock()
		return err
	}
	c.Stamp(c.now())
	return nil
}
