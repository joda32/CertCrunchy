package pipeline

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/joda32/certcrunchy/internal/certscan"
	"github.com/joda32/certcrunchy/internal/logx"
	"github.com/joda32/certcrunchy/internal/resolve"
	"github.com/joda32/certcrunchy/internal/source"
)

type fakeSource struct {
	info  source.Info
	names []string
	err   error
	calls atomic.Int32
}

func (f *fakeSource) Info() source.Info { return f.info }
func (f *fakeSource) Enumerate(_ context.Context, _ string, emit func(string)) error {
	f.calls.Add(1)
	for _, n := range f.names {
		emit(n)
	}
	return f.err
}

func hostNames(res *Result) []string {
	var out []string
	for _, h := range res.Hosts {
		out = append(out, h.Name)
	}
	slices.Sort(out)
	return out
}

func find(res *Result, name string) *Host {
	for _, h := range res.Hosts {
		if h.Name == name {
			return h
		}
	}
	return nil
}

func TestFallbackRunsOnlyWhenPrimaryFails(t *testing.T) {
	for _, tc := range []struct {
		name         string
		primaryErr   error
		wantFallback bool
	}{
		{"primary ok", nil, false},
		{"primary failed", errors.New("connection refused"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary := &fakeSource{info: source.Info{Name: "crtsh-db"}, names: []string{"a.example.com"}, err: tc.primaryErr}
			fallback := &fakeSource{info: source.Info{Name: "crtsh", FallbackFor: "crtsh-db"}, names: []string{"b.example.com"}}
			res, err := Run(context.Background(), Options{
				Domains: []string{"example.com"}, Sources: []source.Source{primary, fallback}, NoResolve: true, Log: logx.Discard(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := fallback.calls.Load() == 1; got != tc.wantFallback {
				t.Fatalf("fallback ran=%v, want %v", got, tc.wantFallback)
			}
			if find(res, "a.example.com") == nil {
				t.Fatal("primary's partial results must be kept")
			}
		})
	}
}

func TestFallbackRunsWhenPrimaryNotSelected(t *testing.T) {
	fallback := &fakeSource{info: source.Info{Name: "crtsh", FallbackFor: "crtsh-db"}, names: []string{"b.example.com"}}
	_, _ = Run(context.Background(), Options{Domains: []string{"example.com"}, Sources: []source.Source{fallback}, NoResolve: true, Log: logx.Discard()})
	if fallback.calls.Load() != 1 {
		t.Fatal("fallback should run when its primary is excluded")
	}
}

func TestScopeDedupeAndHealth(t *testing.T) {
	s1 := &fakeSource{info: source.Info{Name: "one"}, names: []string{"*.a.example.com", "A.example.com", "evil-example.com", "x.other.net", "admin@example.com"}}
	s2 := &fakeSource{info: source.Info{Name: "two"}, names: []string{"a.example.com", "b.example.com"}}
	s3 := &fakeSource{info: source.Info{Name: "three"}, err: errors.New("boom")}
	res, _ := Run(context.Background(), Options{
		Domains: []string{"example.com"}, Sources: []source.Source{s1, s2, s3}, NoResolve: true, Log: logx.Discard(),
	})
	if got := hostNames(res); !slices.Equal(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("hosts = %v", got)
	}
	if h := find(res, "a.example.com"); !slices.Equal(h.Sources, []string{"one", "two"}) {
		t.Fatalf("sources = %v", h.Sources)
	}
	counts := map[string]Health{}
	for _, h := range res.Health {
		counts[h.Source] = h
	}
	if counts["one"].Count != 1 || counts["two"].Count != 2 || counts["three"].Status != StatusError {
		t.Fatalf("health = %+v", res.Health)
	}
}

func TestSourceTimeout(t *testing.T) {
	slow := &blockingSource{}
	res, _ := Run(context.Background(), Options{
		Domains: []string{"example.com"}, Sources: []source.Source{slow}, NoResolve: true,
		SourceTimeout: 50 * time.Millisecond, Log: logx.Discard(),
	})
	if res.Health[0].Status != StatusTimeout {
		t.Fatalf("health = %+v", res.Health)
	}
}

type blockingSource struct{}

func (blockingSource) Info() source.Info { return source.Info{Name: "slow"} }
func (blockingSource) Enumerate(ctx context.Context, _ string, _ func(string)) error {
	<-ctx.Done()
	return ctx.Err()
}

// ---- netblock end-to-end ----

func cert(t *testing.T, cn string, sans []string, org string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{org}},
		DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func dnsServer(t *testing.T, records map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		key := strings.ToLower(q.Name) + " " + dns.TypeToString[q.Qtype]
		if rr, ok := records[key]; ok {
			r, err := dns.NewRR(q.Name + " 60 IN " + dns.TypeToString[q.Qtype] + " " + rr)
			if err != nil {
				t.Error(err)
			}
			m.Answer = append(m.Answer, r)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestNetblockEndToEnd(t *testing.T) {
	def := cert(t, "default.lab.test", []string{"default.lab.test", "vhost.lab.test"}, "Lab Corp")
	hidden := cert(t, "secret.lab.test", []string{"secret.lab.test"}, "Lab Corp")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "vhost.lab.test" {
			return &hidden, nil
		}
		return &def, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	srv := dnsServer(t, map[string]string{
		"default.lab.test. A":         "127.0.0.1",
		"vhost.lab.test. A":           "127.0.0.1",
		"1.0.0.127.in-addr.arpa. PTR": "ptr.lab.test.",
	})
	rng, _ := certscan.ParseRanges([]string{"127.0.0.1/32"})
	res, err := Run(context.Background(), Options{
		Ranges: rng, Ports: []int{port},
		Scanner:  &certscan.Scanner{Timeout: time.Second, Concurrency: 4},
		Resolver: resolve.New([]string{srv}, time.Second),
		PTR:      true, SNI: true, Log: logx.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default.lab.test", "ptr.lab.test", "secret.lab.test", "vhost.lab.test"}
	if got := hostNames(res); !slices.Equal(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
	d := find(res, "default.lab.test")
	if !d.Resolved || !d.InRange || len(d.Certs) == 0 || d.Certs[0].Organization[0] != "Lab Corp" {
		t.Fatalf("default host = %+v", d)
	}
	if s := find(res, "secret.lab.test"); !slices.Equal(s.Sources, []string{SrcSNI}) || s.Resolved {
		t.Fatalf("secret host = %+v", s)
	}
	if p := find(res, "ptr.lab.test"); !slices.Equal(p.Sources, []string{SrcPTR}) {
		t.Fatalf("ptr host = %+v", p)
	}
}

func TestPlaceholderOrg(t *testing.T) {
	if !placeholderOrg("Internet Widgits Pty Ltd") || placeholderOrg("CyberCorp Pty Ltd") {
		t.Fatal("placeholder detection wrong")
	}
}

func TestHostLess(t *testing.T) {
	in := []string{"b.example.com", "a.example.org", "example.com", "a.example.com"}
	slices.SortFunc(in, func(a, b string) int {
		if hostLess(a, b) {
			return -1
		}
		if hostLess(b, a) {
			return 1
		}
		return 0
	})
	if !slices.Equal(in, []string{"example.com", "a.example.com", "b.example.com", "a.example.org"}) {
		t.Fatalf("order = %v", in)
	}
}

func TestPartialStatus(t *testing.T) {
	s := &fakeSource{info: source.Info{Name: "p"}, names: []string{"a.example.com"}, err: errors.New("HTTP 429")}
	res, _ := Run(context.Background(), Options{Domains: []string{"example.com"}, Sources: []source.Source{s}, NoResolve: true, Log: logx.Discard()})
	if h := res.Health[0]; h.Status != StatusPartial || h.Count != 1 || !strings.Contains(h.Error, "HTTP 429") {
		t.Fatalf("health = %+v", h)
	}
}
