// Package pipeline orchestrates a CertCrunchy run: passive sources per
// domain, the netblock certificate/PTR sweep, optional pivots, DNS
// validation and the SNI pass.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/joda32/certcrunchy/internal/certscan"
	"github.com/joda32/certcrunchy/internal/httpx"
	"github.com/joda32/certcrunchy/internal/logx"
	"github.com/joda32/certcrunchy/internal/names"
	"github.com/joda32/certcrunchy/internal/resolve"
	"github.com/joda32/certcrunchy/internal/source"
)

// Netblock-derived pseudo sources.
const (
	SrcCertScan  = "certscan"
	SrcSNI       = "sni"
	SrcPTR       = "ptr"
	SrcVTIP      = "virustotal-ip"
	SrcOrgPivot  = "org-pivot"
	maxCertsHost = 10
)

type Options struct {
	Domains []string
	Sources []source.Source // selected domain sources (fallbacks included)

	Ranges  *certscan.Range
	Ports   []int
	Scanner *certscan.Scanner
	PTR     bool
	VT      *source.VirusTotal // non-nil enables the VirusTotal IP sweep
	CTLogs  *source.CTLogs     // used by OrgPivot

	Resolver           *resolve.Resolver
	NoResolve          bool
	ResolveConcurrency int

	SNI         bool
	Pivot       bool
	PivotMax    int
	OrgPivot    bool
	OrgPivotMax int

	SourceTimeout     time.Duration
	DomainConcurrency int
	Delay             time.Duration // pause between starting domains

	Log *logx.Logger
}

// Host is one discovered name with everything known about it.
type Host struct {
	Name     string               `json:"host"`
	Resolved bool                 `json:"resolved"`
	IPs      []string             `json:"ips,omitempty"`
	CNAMEs   []string             `json:"cnames,omitempty"`
	Wildcard bool                 `json:"wildcard,omitempty"`
	InRange  bool                 `json:"in_range,omitempty"`
	Sources  []string             `json:"sources"`
	Certs    []*certscan.Sighting `json:"certs,omitempty"`
	srcSet   map[string]bool
}

type Status string

const (
	StatusOK          Status = "ok"
	StatusEmpty       Status = "empty"
	StatusPartial     Status = "partial" // failed part-way but returned names
	StatusRateLimited Status = "rate-limited"
	StatusTimeout     Status = "timeout"
	StatusError       Status = "error"
	StatusSkipped     Status = "skipped"
)

// Health records how one source fared for one target.
type Health struct {
	Source   string        `json:"source"`
	Target   string        `json:"target"`
	Status   Status        `json:"status"`
	Count    int           `json:"count"`
	Duration time.Duration `json:"duration_ns"`
	Error    string        `json:"error,omitempty"`
}

type Result struct {
	Hosts  []*Host  `json:"hosts"`
	Health []Health `json:"health"`
}

type run struct {
	o       Options
	mu      sync.Mutex
	hosts   map[string]*Host
	health  []Health
	queried map[string]bool // domains already sent to passive sources
	orgs    map[string]int
	apexes  map[string]int
}

func Run(ctx context.Context, o Options) (*Result, error) {
	if o.DomainConcurrency <= 0 {
		o.DomainConcurrency = 4
	}
	if o.ResolveConcurrency <= 0 {
		o.ResolveConcurrency = 50
	}
	if o.SourceTimeout <= 0 {
		o.SourceTimeout = 3 * time.Minute
	}
	r := &run{o: o, hosts: map[string]*Host{}, queried: map[string]bool{}, orgs: map[string]int{}, apexes: map[string]int{}}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { r.domainPhase(gctx, o.Domains); return nil })
	if o.Ranges != nil {
		g.Go(func() error { r.netblockPhase(gctx); return nil })
	}
	_ = g.Wait()
	if err := ctx.Err(); err != nil {
		return r.result(), err
	}

	if o.Pivot {
		r.pivotDomains(ctx)
	}
	if o.OrgPivot && o.CTLogs != nil {
		r.pivotOrgs(ctx)
	}
	if !o.NoResolve && o.Resolver != nil {
		r.resolveAll(ctx)
		if o.SNI && o.Ranges != nil && o.Scanner != nil {
			r.sniPass(ctx)
		}
	}
	return r.result(), ctx.Err()
}

// add records name from src. When scope is non-empty only in-scope names are
// kept. It returns the normalised name ("" if rejected) and whether no other
// source had reported it yet.
func (r *run) add(raw, src, scope string) (string, bool) {
	n, ok := names.Normalize(raw)
	if !ok || (scope != "" && !names.InScope(n, scope)) {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h, exists := r.hosts[n]
	if !exists {
		h = &Host{Name: n, srcSet: map[string]bool{}}
		r.hosts[n] = h
	}
	h.srcSet[src] = true
	return n, !exists
}

func (r *run) record(h Health) {
	r.mu.Lock()
	r.health = append(r.health, h)
	r.mu.Unlock()
	d := h.Duration.Round(10 * time.Millisecond)
	switch h.Status {
	case StatusOK, StatusEmpty:
		r.o.Log.Info("%-13s %-28s %5d names  %s", h.Source, h.Target, h.Count, d)
	case StatusPartial:
		r.o.Log.Warn("%-13s %-28s %5d names  %s (partial — %s)", h.Source, h.Target, h.Count, d, h.Error)
	default:
		r.o.Log.Warn("%-13s %-28s %s: %s (%s)", h.Source, h.Target, h.Status, h.Error, d)
	}
}

func classify(err error, count int) (Status, string) {
	st, msg := classifyErr(err, count)
	if count > 0 && st != StatusOK {
		return StatusPartial, string(st) + ": " + msg
	}
	return st, msg
}

func classifyErr(err error, count int) (Status, string) {
	switch {
	case err == nil && count > 0:
		return StatusOK, ""
	case err == nil:
		return StatusEmpty, ""
	case errors.Is(err, httpx.ErrRateLimited):
		return StatusRateLimited, err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return StatusTimeout, "timed out"
	default:
		return StatusError, err.Error()
	}
}

// ---- passive sources ----

func (r *run) domainPhase(ctx context.Context, domains []string) {
	sem := make(chan struct{}, r.o.DomainConcurrency)
	var wg sync.WaitGroup
	for i, d := range domains {
		r.mu.Lock()
		dup := r.queried[d]
		r.queried[d] = true
		r.mu.Unlock()
		if dup {
			continue
		}
		if i > 0 && r.o.Delay > 0 {
			select {
			case <-time.After(r.o.Delay):
			case <-ctx.Done():
				return
			}
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			r.enumerateDomain(ctx, d)
		}(d)
	}
	wg.Wait()
}

func (r *run) enumerateDomain(ctx context.Context, domain string) {
	var primaries, fallbacks []source.Source
	selected := map[string]bool{}
	for _, s := range r.o.Sources {
		selected[s.Info().Name] = true
		if s.Info().FallbackFor != "" {
			fallbacks = append(fallbacks, s)
		} else {
			primaries = append(primaries, s)
		}
	}
	status := r.runSources(ctx, domain, primaries)
	var need []source.Source
	for _, f := range fallbacks {
		p := f.Info().FallbackFor
		if st, ran := status[p]; !selected[p] || (ran && st != StatusOK && st != StatusEmpty) {
			need = append(need, f)
		}
	}
	if len(need) > 0 && ctx.Err() == nil {
		r.runSources(ctx, domain, need)
	}
}

func (r *run) runSources(ctx context.Context, domain string, srcs []source.Source) map[string]Status {
	out := map[string]Status{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range srcs {
		wg.Add(1)
		go func(s source.Source) {
			defer wg.Done()
			name := s.Info().Name
			sctx, cancel := context.WithTimeout(ctx, r.o.SourceTimeout)
			defer cancel()
			start := time.Now()
			seen := map[string]bool{}
			var smu sync.Mutex
			err := s.Enumerate(sctx, domain, func(raw string) {
				if n, _ := r.add(raw, name, domain); n != "" {
					smu.Lock()
					seen[n] = true
					smu.Unlock()
				}
			})
			if err != nil && sctx.Err() != nil && ctx.Err() == nil {
				err = context.DeadlineExceeded
			}
			st, msg := classify(err, len(seen))
			r.record(Health{Source: name, Target: domain, Status: st, Count: len(seen), Duration: time.Since(start), Error: msg})
			mu.Lock()
			out[name] = st
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return out
}

// ---- netblock ----

func (r *run) netblockPhase(ctx context.Context) {
	var wg sync.WaitGroup
	if r.o.Scanner != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.certScan(ctx) }()
	}
	if r.o.PTR && r.o.Resolver != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.ptrSweep(ctx) }()
	}
	if r.o.VT != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.vtSweep(ctx) }()
	}
	wg.Wait()
}

func (r *run) target() string {
	var parts []string
	for _, p := range r.o.Ranges.Prefixes {
		parts = append(parts, p.String())
	}
	s := strings.Join(parts, ",")
	if len(s) > 28 {
		s = s[:27] + "…"
	}
	return s
}

func (r *run) certScan(ctx context.Context) {
	start := time.Now()
	found := map[string]bool{}
	endpoints := 0
	r.o.Scanner.Scan(ctx, r.o.Ranges.Targets(r.o.Ports), func(sg *certscan.Sighting) {
		endpoints++
		r.o.Log.Debug("certscan %s:%d -> %s", sg.IP, sg.Port, strings.Join(sg.Names, ", "))
		var outside []string
		for _, ip := range sg.IPSANs {
			if a, err := netip.ParseAddr(ip); err == nil && !r.o.Ranges.Contains(a) {
				outside = append(outside, ip)
			}
		}
		if len(outside) > 0 {
			r.o.Log.Info("certscan %s:%d cert also lists IPs outside the range: %s", sg.IP, sg.Port, strings.Join(outside, ", "))
		}
		for _, raw := range sg.Names {
			if n, _ := r.add(raw, SrcCertScan, ""); n != "" {
				found[n] = true
				r.attach(n, sg)
			}
		}
		r.mu.Lock()
		for _, o := range sg.Organization {
			if o = strings.TrimSpace(o); o != "" && !placeholderOrg(o) {
				r.orgs[o]++
			}
		}
		for _, n := range sg.Names {
			if a := names.Apex(n); a != "" {
				r.apexes[a]++
			}
		}
		r.mu.Unlock()
	}, nil)
	st, msg := classify(ctx.Err(), len(found))
	h := Health{Source: SrcCertScan, Target: r.target(), Status: st, Count: len(found), Duration: time.Since(start), Error: msg}
	r.record(h)
	r.o.Log.Info("certscan: certificates on %d endpoints", endpoints)
}

func (r *run) attach(name string, sg *certscan.Sighting) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.hosts[name]
	for _, c := range h.Certs {
		if c.IP == sg.IP && c.Port == sg.Port && c.SNI == sg.SNI {
			return
		}
	}
	if len(h.Certs) < maxCertsHost {
		h.Certs = append(h.Certs, sg)
	}
}

func (r *run) ptrSweep(ctx context.Context) {
	start := time.Now()
	addrs := make(chan netip.Addr)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := map[string]bool{}
	for range r.o.ResolveConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range addrs {
				ptrs, err := r.o.Resolver.PTR(ctx, a)
				if err != nil {
					continue
				}
				for _, p := range ptrs {
					if n, _ := r.add(p, SrcPTR, ""); n != "" {
						mu.Lock()
						found[n] = true
						mu.Unlock()
					}
				}
			}
		}()
	}
feed:
	for a := range r.o.Ranges.Addrs() {
		select {
		case addrs <- a:
		case <-ctx.Done():
			break feed
		}
	}
	close(addrs)
	wg.Wait()
	st, msg := classify(ctx.Err(), len(found))
	r.record(Health{Source: SrcPTR, Target: r.target(), Status: st, Count: len(found), Duration: time.Since(start), Error: msg})
}

func (r *run) vtSweep(ctx context.Context) {
	start := time.Now()
	found := map[string]bool{}
	var lastErr error
	for a := range r.o.Ranges.Addrs() {
		err := r.o.VT.IPResolutions(ctx, a, func(raw string) {
			if n, _ := r.add(raw, SrcVTIP, ""); n != "" {
				found[n] = true
			}
		})
		if err != nil {
			lastErr = err
			if errors.Is(err, httpx.ErrRateLimited) || ctx.Err() != nil {
				break // quota exhausted: stop instead of hammering
			}
		}
	}
	st, msg := classify(lastErr, len(found))
	r.record(Health{Source: SrcVTIP, Target: r.target(), Status: st, Count: len(found), Duration: time.Since(start), Error: msg})
}

// ---- pivots ----

// pivotDomains feeds registrable domains seen in netblock certificates back
// into the passive sources (depth 1), most frequently seen first.
func (r *run) pivotDomains(ctx context.Context) {
	r.mu.Lock()
	var cands []string
	for a := range r.apexes {
		if !r.queried[a] {
			cands = append(cands, a)
		}
	}
	counts := r.apexes
	r.mu.Unlock()
	sort.Slice(cands, func(i, j int) bool {
		if counts[cands[i]] != counts[cands[j]] {
			return counts[cands[i]] > counts[cands[j]]
		}
		return cands[i] < cands[j]
	})
	if r.o.PivotMax > 0 && len(cands) > r.o.PivotMax {
		r.o.Log.Warn("pivot: %d domains found, querying the top %d (raise --pivot-max for more)", len(cands), r.o.PivotMax)
		cands = cands[:r.o.PivotMax]
	}
	if len(cands) == 0 {
		return
	}
	r.o.Log.Info("pivot: querying passive sources for %s", strings.Join(cands, ", "))
	r.domainPhase(ctx, cands)
}

// pivotOrgs searches CT for other certificates issued to the organisations
// seen in netblock certificates.
func (r *run) pivotOrgs(ctx context.Context) {
	r.mu.Lock()
	var orgs []string
	for o := range r.orgs {
		orgs = append(orgs, o)
	}
	counts := r.orgs
	r.mu.Unlock()
	sort.Slice(orgs, func(i, j int) bool {
		if counts[orgs[i]] != counts[orgs[j]] {
			return counts[orgs[i]] > counts[orgs[j]]
		}
		return orgs[i] < orgs[j]
	})
	if r.o.OrgPivotMax > 0 && len(orgs) > r.o.OrgPivotMax {
		orgs = orgs[:r.o.OrgPivotMax]
	}
	for _, org := range orgs {
		start := time.Now()
		found := map[string]bool{}
		err := r.o.CTLogs.OrgSearch(ctx, org, 3, func(raw string) {
			if n, _ := r.add(raw, SrcOrgPivot, ""); n != "" {
				found[n] = true
			}
		})
		st, msg := classify(err, len(found))
		r.record(Health{Source: SrcOrgPivot, Target: fmt.Sprintf("O=%q", org), Status: st, Count: len(found), Duration: time.Since(start), Error: msg})
	}
}

var placeholderOrgs = []string{
	"internet widgits pty ltd", "default company ltd", "someorganization", "some-organization",
	"acme co", "unspecified", "none", "example", "my company", "company", "test", "localhost",
	"org", "organization", "mycompany", "self-signed", "-",
}

func placeholderOrg(o string) bool {
	l := strings.ToLower(strings.TrimSpace(o))
	for _, p := range placeholderOrgs {
		if l == p {
			return true
		}
	}
	return len(l) < 3
}

// ---- resolution ----

func (r *run) resolveAll(ctx context.Context) {
	r.mu.Lock()
	var todo []*Host
	for _, h := range r.hosts {
		todo = append(todo, h)
	}
	r.mu.Unlock()
	r.resolveHosts(ctx, todo)
}

func (r *run) resolveHosts(ctx context.Context, todo []*Host) {
	start := time.Now()
	r.o.Log.Info("resolving %d names (A/AAAA) via %s", len(todo), strings.Join(r.o.Resolver.Servers(), ", "))
	jobs := make(chan *Host)
	var wg sync.WaitGroup
	for range r.o.ResolveConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				ans, err := r.o.Resolver.Lookup(ctx, h.Name)
				if err != nil {
					r.o.Log.Debug("resolve %s: %v", h.Name, err)
				}
				wild := r.o.Resolver.IsWildcard(ctx, h.Name, ans)
				inRange := false
				if r.o.Ranges != nil {
					for _, ip := range ans.IPs {
						if a, err := netip.ParseAddr(ip); err == nil && r.o.Ranges.Contains(a) {
							inRange = true
						}
					}
				}
				r.mu.Lock()
				h.IPs, h.CNAMEs, h.Resolved, h.Wildcard, h.InRange = ans.IPs, ans.CNAMEs, ans.Resolved(), wild, inRange
				r.mu.Unlock()
			}
		}()
	}
feed:
	for _, h := range todo {
		select {
		case jobs <- h:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	n := 0
	for _, h := range todo {
		if h.Resolved {
			n++
		}
	}
	r.o.Log.Info("resolved %d/%d names in %s", n, len(todo), time.Since(start).Round(10*time.Millisecond))
}

// sniPass re-handshakes with each resolved name whose address lies inside the
// scanned range, revealing certificates for virtual hosts that are not the
// default on that IP. New names are then resolved too.
func (r *run) sniPass(ctx context.Context) {
	start := time.Now()
	r.mu.Lock()
	var targets []certscan.Target
	for _, h := range r.hosts {
		if !h.InRange || h.Wildcard {
			continue
		}
		for _, ip := range h.IPs {
			a, err := netip.ParseAddr(ip)
			if err != nil || !r.o.Ranges.Contains(a) {
				continue
			}
			for _, p := range r.o.Ports {
				targets = append(targets, certscan.Target{Addr: a, Port: p, SNI: h.Name})
			}
		}
	}
	r.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	r.o.Log.Info("sni: re-probing %d endpoint/name pairs inside the range", len(targets))
	var fresh []string
	r.o.Scanner.Scan(ctx, func(yield func(certscan.Target) bool) {
		for _, t := range targets {
			if !yield(t) {
				return
			}
		}
	}, func(sg *certscan.Sighting) {
		for _, raw := range sg.Names {
			n, isNew := r.add(raw, SrcSNI, "")
			if n == "" {
				continue
			}
			if isNew {
				fresh = append(fresh, n)
			}
			r.attach(n, sg)
		}
	}, nil)
	st, msg := classify(ctx.Err(), len(fresh))
	r.record(Health{Source: SrcSNI, Target: r.target(), Status: st, Count: len(fresh), Duration: time.Since(start), Error: msg})
	if len(fresh) > 0 {
		var hs []*Host
		r.mu.Lock()
		for _, n := range fresh {
			hs = append(hs, r.hosts[n])
		}
		r.mu.Unlock()
		r.resolveHosts(ctx, hs)
	}
}

func (r *run) result() *Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := &Result{Health: append([]Health(nil), r.health...)}
	for _, h := range r.hosts {
		h.Sources = h.Sources[:0]
		for s := range h.srcSet {
			h.Sources = append(h.Sources, s)
		}
		sort.Strings(h.Sources)
		res.Hosts = append(res.Hosts, h)
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return hostLess(res.Hosts[i].Name, res.Hosts[j].Name) })
	return res
}

// hostLess sorts by reversed labels so names group by parent domain.
func hostLess(a, b string) bool {
	ra, rb := strings.Split(a, "."), strings.Split(b, ".")
	for i, j := len(ra)-1, len(rb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if ra[i] != rb[j] {
			return ra[i] < rb[j]
		}
	}
	return len(ra) < len(rb)
}
