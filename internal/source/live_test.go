//go:build live

package source

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joda32/certcrunchy/internal/config"
	"github.com/joda32/certcrunchy/internal/httpx"
	"github.com/joda32/certcrunchy/internal/names"
)

// Live smoke tests: one real query per usable source.
//
//	go test -tags live -run Live -v ./internal/source/
//	LIVE_DOMAIN=example.org LIVE_SOURCES=crtsh-db,certspotter go test -tags live ...
func TestLiveSources(t *testing.T) {
	domain := os.Getenv("LIVE_DOMAIN")
	if domain == "" {
		domain = "example.com"
	}
	only := map[string]bool{}
	for _, n := range splitComma(os.Getenv("LIVE_SOURCES")) {
		only[n] = true
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range All(Deps{HTTP: httpx.New(90*time.Second, "live-test"), Cfg: cfg}) {
		info := s.Info()
		if len(only) > 0 && !only[info.Name] {
			continue
		}
		t.Run(info.Name, func(t *testing.T) {
			if !info.Usable() {
				t.Skip("no key configured")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			found := map[string]bool{}
			start := time.Now()
			err := s.Enumerate(ctx, domain, func(raw string) {
				if n, ok := names.Normalize(raw); ok && names.InScope(n, domain) {
					found[n] = true
				}
			})
			t.Logf("%s: %d names in %s (err=%v)", info.Name, len(found), time.Since(start).Round(time.Millisecond), err)
			if err != nil {
				t.Skipf("source unavailable right now: %v", err)
			}
		})
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
