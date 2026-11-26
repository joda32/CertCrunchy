// Package certscan harvests hostnames from the TLS certificates served by
// hosts in a netblock: CertCrunchy's original trick.
//
// Connecting by IP without SNI makes most servers present their default
// certificate, whose CN/SANs often name hosts that never show up anywhere else
// (internal names, appliances, forgotten vhosts). Certificates are captured in
// VerifyPeerCertificate *before* any validation, so self-signed, private-CA,
// expired and otherwise broken certificates are all harvested, and the cert is
// kept even when the server aborts the handshake afterwards (e.g. mTLS).
package certscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/names"
)

// Target is one TLS endpoint to probe. SNI empty means no SNI is sent.
type Target struct {
	Addr netip.Addr
	Port int
	SNI  string
}

func (t Target) String() string {
	s := netip.AddrPortFrom(t.Addr, uint16(t.Port)).String()
	if t.SNI != "" {
		s += " (sni " + t.SNI + ")"
	}
	return s
}

// Sighting is a certificate observed on an endpoint.
type Sighting struct {
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	SNI          string    `json:"sni,omitempty"`
	Names        []string  `json:"-"`
	CommonName   string    `json:"cn,omitempty"`
	Organization []string  `json:"org,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SelfSigned   bool      `json:"self_signed,omitempty"`
	Expired      bool      `json:"expired,omitempty"`
	NotAfter     time.Time `json:"not_after"`
	SHA256       string    `json:"sha256"`
	IPSANs       []string  `json:"ip_sans,omitempty"` // iPAddress SANs (and an IP-literal CN)
}

type Scanner struct {
	Timeout     time.Duration // TCP connect timeout; handshake gets 2x
	Concurrency int
	Limiter     *rate.Limiter // optional global connection rate
}

var allSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

// Grab connects to t and returns the leaf certificate it presents.
func (s *Scanner) Grab(ctx context.Context, t Target) (*Sighting, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if s.Limiter != nil {
		if err := s.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(t.Addr, uint16(t.Port)).String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * timeout))

	var leaf *x509.Certificate
	var parseErr error
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // recon: we want every certificate, trusted or not
		ServerName:         t.SNI,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allSuites,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) > 0 {
				leaf, parseErr = x509.ParseCertificate(raw[0])
			}
			return nil
		},
	}
	tc := tls.Client(conn, cfg)
	hsErr := tc.HandshakeContext(ctx)
	if leaf == nil {
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate: %w", parseErr)
		}
		if hsErr != nil {
			return nil, hsErr
		}
		return nil, errors.New("no certificate presented")
	}
	return describe(t, leaf), nil
}

func describe(t Target, c *x509.Certificate) *Sighting {
	sum := sha256.Sum256(c.Raw)
	sg := &Sighting{
		IP:           t.Addr.String(),
		Port:         t.Port,
		SNI:          t.SNI,
		CommonName:   c.Subject.CommonName,
		Organization: c.Subject.Organization,
		Issuer:       issuerName(c),
		SelfSigned:   bytes.Equal(c.RawIssuer, c.RawSubject),
		Expired:      time.Now().After(c.NotAfter),
		NotAfter:     c.NotAfter,
		SHA256:       hex.EncodeToString(sum[:]),
	}
	seen := map[string]bool{}
	add := func(raw string) {
		if n, ok := names.Normalize(raw); ok && !seen[n] {
			seen[n] = true
			sg.Names = append(sg.Names, n)
		}
	}
	add(c.Subject.CommonName)
	for _, n := range c.DNSNames {
		add(n)
	}
	// rfc822Name SANs: the mail domain is often a real internal host/zone.
	for _, e := range c.EmailAddresses {
		if i := strings.LastIndexByte(e, '@'); i >= 0 {
			add(e[i+1:])
		}
	}
	// URI SANs: keep the host part (e.g. https://portal.corp.internal/).
	for _, u := range c.URIs {
		add(u.Hostname())
	}

	ipSeen := map[string]bool{}
	addIP := func(a netip.Addr) {
		if s := a.Unmap().String(); a.IsValid() && !ipSeen[s] {
			ipSeen[s] = true
			sg.IPSANs = append(sg.IPSANs, s)
		}
	}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			addIP(a)
		}
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(c.Subject.CommonName)); err == nil {
		addIP(a)
	}
	sort.Strings(sg.Names)
	sort.Strings(sg.IPSANs)
	return sg
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.String()
}

// Scan probes every target with a bounded worker pool and calls emit (from
// multiple goroutines, serialised) for each certificate found.
func (s *Scanner) Scan(ctx context.Context, targets iter.Seq[Target], emit func(*Sighting), onErr func(Target, error)) {
	workers := s.Concurrency
	if workers <= 0 {
		workers = 100
	}
	jobs := make(chan Target)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				sg, err := s.Grab(ctx, t)
				mu.Lock()
				if err != nil {
					if onErr != nil {
						onErr(t, err)
					}
				} else {
					emit(sg)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
}

// Range is a parsed set of addresses to scan.
type Range struct {
	Prefixes []netip.Prefix
	Size     *big.Int // total addresses
}

// ParseRanges accepts CIDRs ("10.0.0.0/24", "2001:db8::/120") and single IPs.
func ParseRanges(specs []string) (*Range, error) {
	r := &Range{Size: new(big.Int)}
	for _, raw := range specs {
		for _, spec := range strings.Split(raw, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			var p netip.Prefix
			var err error
			if strings.Contains(spec, "/") {
				p, err = netip.ParsePrefix(spec)
			} else {
				var a netip.Addr
				a, err = netip.ParseAddr(spec)
				if err == nil {
					p = netip.PrefixFrom(a, a.BitLen())
				}
			}
			if err != nil {
				return nil, fmt.Errorf("invalid IP range %q: %w", spec, err)
			}
			p = p.Masked()
			r.Prefixes = append(r.Prefixes, p)
			host := p.Addr().BitLen() - p.Bits()
			r.Size.Add(r.Size, new(big.Int).Lsh(big.NewInt(1), uint(host)))
		}
	}
	if len(r.Prefixes) == 0 {
		return nil, errors.New("no IP ranges given")
	}
	return r, nil
}

// Contains reports whether a is inside any prefix.
func (r *Range) Contains(a netip.Addr) bool {
	for _, p := range r.Prefixes {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// Addrs yields every address in the range.
func (r *Range) Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for _, p := range r.Prefixes {
			for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
				if !yield(a) {
					return
				}
			}
		}
	}
}

// Targets yields addr×port combinations, ports varying fastest.
func (r *Range) Targets(ports []int) iter.Seq[Target] {
	return func(yield func(Target) bool) {
		for a := range r.Addrs() {
			for _, p := range ports {
				if !yield(Target{Addr: a, Port: p}) {
					return
				}
			}
		}
	}
}

// Port presets usable in -p alongside numbers.
var presets = map[string][]int{
	"web":  {443, 8443, 4443, 9443, 10443},
	"mail": {465, 993, 995},
	"all":  {443, 8443, 4443, 9443, 10443, 465, 993, 995, 636, 3269, 989, 990, 5061, 5986, 8883, 6443, 2376},
}

// ParsePorts parses "443,8443,web" into a de-duplicated port list.
func ParsePorts(specs []string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range specs {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			if ps, ok := presets[s]; ok {
				for _, p := range ps {
					add(p)
				}
				continue
			}
			p, err := strconv.Atoi(s)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", s)
			}
			add(p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports given")
	}
	return out, nil
}
