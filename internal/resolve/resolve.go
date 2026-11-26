// Package resolve validates candidate names with DNS (A, AAAA, CNAME), does
// PTR lookups, and detects wildcard zones so wildcard-matched names can be
// flagged instead of reported as real hosts.
package resolve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var fallbackServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

type Resolver struct {
	servers []string
	client  *dns.Client
	retries int
	next    atomic.Uint64
	wild    sync.Map // parent zone -> *wildEntry
}

// New builds a resolver. With no servers it uses /etc/resolv.conf and falls
// back to public resolvers.
func New(servers []string, timeout time.Duration) *Resolver {
	var list []string
	for _, s := range servers {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, withPort(p))
			}
		}
	}
	if len(list) == 0 {
		if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
			for _, s := range cc.Servers {
				list = append(list, net.JoinHostPort(s, cc.Port))
			}
		}
	}
	if len(list) == 0 {
		list = fallbackServers
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Resolver{servers: list, client: &dns.Client{Timeout: timeout}, retries: 3}
}

func withPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

func (r *Resolver) Servers() []string { return r.servers }

var errServFail = errors.New("SERVFAIL")

// exchange sends one query, rotating servers and retrying on failure. It
// retries over TCP when the UDP answer is truncated.
func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	var lastErr error
	for i := 0; i < r.retries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		srv := r.servers[r.next.Add(1)%uint64(len(r.servers))]
		resp, _, err := r.client.ExchangeContext(ctx, m, srv)
		if err == nil && resp.Truncated {
			tcp := *r.client
			tcp.Net = "tcp"
			resp, _, err = tcp.ExchangeContext(ctx, m, srv)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			lastErr = errServFail
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// Answer is the result of resolving one name.
type Answer struct {
	IPs    []string
	CNAMEs []string
}

func (a Answer) Resolved() bool { return len(a.IPs) > 0 }

// Lookup resolves A and AAAA for name. An NXDOMAIN or empty answer is not an
// error; err is set only when every attempt failed.
func (r *Resolver) Lookup(ctx context.Context, name string) (Answer, error) {
	type res struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan res, 2)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func(qt uint16) {
			m, err := r.exchange(ctx, name, qt)
			ch <- res{m, err}
		}(qt)
	}
	var ans Answer
	var errs int
	var lastErr error
	for range 2 {
		x := <-ch
		if x.err != nil {
			errs++
			lastErr = x.err
			continue
		}
		for _, rr := range x.msg.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ans.IPs = append(ans.IPs, v.A.String())
			case *dns.AAAA:
				ans.IPs = append(ans.IPs, v.AAAA.String())
			case *dns.CNAME:
				ans.CNAMEs = append(ans.CNAMEs, strings.TrimSuffix(strings.ToLower(v.Target), "."))
			}
		}
	}
	ans.IPs = uniqSorted(ans.IPs)
	ans.CNAMEs = uniq(ans.CNAMEs)
	if errs == 2 {
		return ans, lastErr
	}
	return ans, nil
}

// PTR returns the reverse names for addr.
func (r *Resolver) PTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	rev, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return nil, err
	}
	m, err := r.exchange(ctx, rev, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range m.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			out = append(out, strings.TrimSuffix(strings.ToLower(p.Ptr), "."))
		}
	}
	return out, nil
}

type wildEntry struct {
	once sync.Once
	ans  Answer
}

// IsWildcard reports whether name's answer looks like it came from a wildcard
// record at its parent zone: a random sibling label also resolves and shares
// an IP or CNAME target with it.
func (r *Resolver) IsWildcard(ctx context.Context, name string, a Answer) bool {
	if !a.Resolved() {
		return false
	}
	i := strings.IndexByte(name, '.')
	if i < 0 || strings.Count(name[i+1:], ".") < 1 {
		return false
	}
	parent := name[i+1:]
	v, _ := r.wild.LoadOrStore(parent, &wildEntry{})
	e := v.(*wildEntry)
	e.once.Do(func() {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		e.ans, _ = r.Lookup(ctx, "cc-"+hex.EncodeToString(b)+"."+parent)
	})
	if !e.ans.Resolved() {
		return false
	}
	for _, ip := range a.IPs {
		if slices.Contains(e.ans.IPs, ip) {
			return true
		}
	}
	if len(a.CNAMEs) > 0 && len(e.ans.CNAMEs) > 0 && a.CNAMEs[len(a.CNAMEs)-1] == e.ans.CNAMEs[len(e.ans.CNAMEs)-1] {
		return true
	}
	return false
}

func uniq(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func uniqSorted(in []string) []string {
	slices.Sort(in)
	return slices.Compact(in)
}
