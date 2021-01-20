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
	cfg := &tls.Config{ServerName: "server"}

	cache.Add(instance, cfg)
	c.Assert(cache.configs, qt.HasLen, 1)

	gotCfg, err := cache.Get(instance)
	c.Assert(err, qt.IsNil)
	c.Assert(gotCfg, qt.CmpEquals(cmpopts.IgnoreUnexported(tls.Config{})), cfg)
}

func TestTLSCache_NotFound(t *testing.T) {
	c := qt.New(t)
	cache := newtlsCache()

	cfg, err := cache.Get("wrong-name")
	c.Assert(err, qt.Not(qt.IsNil))
	c.Assert(cfg, qt.IsNil)
	c.Assert(err, qt.Equals, errConfigNotFound)
}

func TestTLSCache_Expired(t *testing.T) {
	c := qt.New(t)
	cache := newtlsCache()

	cache.nowFn = func() time.Time {
		return time.Now().Add(-(expireTTL + time.Minute))
	}

	instance := "foo"
	cfg := &tls.Config{ServerName: "server"}

	cache.Add(instance, cfg)

	cfg, err := cache.Get("foo")
	c.Assert(err, qt.Not(qt.IsNil))
	c.Assert(cfg, qt.IsNil)

	// we'll get this because expired keys are removed from the cache
	c.Assert(err, qt.Equals, errConfigNotFound)
	c.Assert(cache.configs, qt.HasLen, 0)
}
