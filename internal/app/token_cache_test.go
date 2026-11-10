package app

import (
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

// A token issued while the watcher was loading the state must not be
// refused: the cache keeps the stamp from before the load, so the changed
// file is noticed on the next lookup (#148).
func TestTokenCacheNoticesWriteDuringLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	loaded, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	cache := newTokenCache(dir, loaded)
	stamp := cache.stat()                               // the watcher stats ...
	secret, _ := issueToken(t, dir, "bob", "10.77.0.2") // ... the administrator issues a token ...
	cache.update(loaded, stamp)                         // ... and the watcher records what it loaded before
	if !cache.has(secret) {
		t.Fatal("token issued during a reload was refused")
	}
}
