// Package source implements the passive hostname sources: Certificate
// Transparency search services and passive DNS APIs.
package source

import (
	"context"
	"net/http"
	"sort"

	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/config"
	"github.com/joda32/certcrunchy/internal/httpx"
)

type Kind string

const (
	CT   Kind = "ct"   // certificate transparency
	PDNS Kind = "pdns" // passive DNS / crawl data
)

// Info describes a source for selection, --list-sources and health output.
type Info struct {
	Name        string
	Kind        Kind
	Desc        string
	KeyName     string // config key name; "" when the source takes no key
	KeyRequired bool
	HasKey      bool
	Default     bool   // runs without --sources when usable
	FallbackFor string // runs only if the named source did not succeed
}

// Usable reports whether the source can run with the configured keys.
func (i Info) Usable() bool { return !i.KeyRequired || i.HasKey }

// Source enumerates names for a domain. emit may be called with raw,
// unnormalised names; callers normalise and scope them.
type Source interface {
	Info() Info
	Enumerate(ctx context.Context, domain string, emit func(string)) error
}

// Deps are the shared dependencies used to construct sources.
type Deps struct {
	HTTP *httpx.Client
	Cfg  *config.Config
}

// All constructs every known source in priority order.
func All(d Deps) []Source {
	k := d.Cfg.Key
	return []Source{
		NewCrtshDB(),
		NewCrtshHTTP(d.HTTP),
		NewCertSpotter(d.HTTP, k("certspotter")),
		NewCTLogs(d.HTTP, k("ctlogs")),
		NewCensys(d.HTTP, k("censys"), k("censys-org")),
		NewMerklemap(d.HTTP, k("merklemap")),
		NewVirusTotal(d.HTTP, k("virustotal")),
		NewHackerTarget(d.HTTP, k("hackertarget")),
		NewOTX(d.HTTP, k("otx")),
		NewURLScan(d.HTTP, k("urlscan")),
		NewRapidDNS(d.HTTP),
	}
}

// Names returns the sorted names of sources.
func Names(srcs []Source) []string {
	var out []string
	for _, s := range srcs {
		out = append(out, s.Info().Name)
	}
	sort.Strings(out)
	return out
}

// base holds what most HTTP sources share.
type base struct {
	info    Info
	key     string
	http    *httpx.Client
	lim     *rate.Limiter
	baseURL string
}

func (b *base) Info() Info {
	i := b.info
	i.HasKey = b.key != ""
	return i
}

func bearer(key string) http.Header {
	h := http.Header{}
	if key != "" {
		h.Set("Authorization", "Bearer "+key)
	}
	return h
}

func header(k, v string) http.Header {
	h := http.Header{}
	if v != "" {
		h.Set(k, v)
	}
	return h
}
