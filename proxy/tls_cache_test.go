package proxy

import (
	"crypto/tls"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestTLSCache_Retrieve(t *testing.T) {
	c := qt.New(t)
	cache := newtlsCache()

	instance := "foo"
	cfg := &tls.Config{ServerName: "server", MinVersion: tls.VersionTLS12}
	remoteAddr := "foo.example.com:3306"

	cache.Add(instance, cfg, remoteAddr)
	c.Assert(cache.configs, qt.HasLen, 1)

	entry, err := cache.Get(instance)
	c.Assert(err, qt.IsNil)
	c.Assert(entry.cfg, qt.CmpEquals(cmpopts.IgnoreUnexported(tls.Config{})), cfg)
	c.Assert(entry.remoteAddr, qt.Equals, remoteAddr)
}

func TestTLSCache_NotFound(t *testing.T) {
	c := qt.New(t)
	cache := newtlsCache()

	entry, err := cache.Get("wrong-name")
	c.Assert(err, qt.Not(qt.IsNil))
	c.Assert(entry, qt.Equals, cacheEntry{})
	c.Assert(err, qt.Equals, errConfigNotFound)
}

func TestTLSCache_Expired(t *testing.T) {
	c := qt.New(t)
	cache := newtlsCache()

	cache.nowFn = func() time.Time {
		return time.Now().Add(-(expireTTL + time.Minute))
	}

	instance := "foo"
	cfg := &tls.Config{ServerName: "server", MinVersion: tls.VersionTLS12}
	remoteAddr := "foo.example.com:3306"

	cache.Add(instance, cfg, remoteAddr)

	entry, err := cache.Get("foo")
	c.Assert(err, qt.Not(qt.IsNil))
	c.Assert(entry, qt.Equals, cacheEntry{})

	// we'll get this because expired keys are removed from the cache
	c.Assert(err, qt.Equals, errConfigNotFound)
	c.Assert(cache.configs, qt.HasLen, 0)
}
