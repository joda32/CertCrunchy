package resolve

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startServer runs an in-process DNS server with a tiny fixed zone.
func startServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		add := func(s string) {
			rr, err := dns.NewRR(s)
			if err != nil {
				t.Error(err)
				return
			}
			m.Answer = append(m.Answer, rr)
		}
		switch {
		case name == "a.example.test." && q.Qtype == dns.TypeA:
			add("a.example.test. 60 IN A 192.0.2.1")
		case name == "a.example.test." && q.Qtype == dns.TypeAAAA:
			add("a.example.test. 60 IN AAAA 2001:db8::1")
		case name == "alias.example.test." && q.Qtype == dns.TypeA:
			add("alias.example.test. 60 IN CNAME a.example.test.")
			add("a.example.test. 60 IN A 192.0.2.1")
		case strings.HasSuffix(name, ".wild.example.test.") && q.Qtype == dns.TypeA:
			add(q.Name + " 60 IN A 192.0.2.9")
		case name == "1.2.0.192.in-addr.arpa." && q.Qtype == dns.TypePTR:
			add("1.2.0.192.in-addr.arpa. 60 IN PTR a.example.test.")
		case name == "fail.example.test.":
			m.Rcode = dns.RcodeServerFailure
		case strings.HasSuffix(name, ".example.test.") || name == "example.test.":
			// NOERROR/NODATA for known zone
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestLookup(t *testing.T) {
	r := New([]string{startServer(t)}, time.Second)
	ctx := context.Background()

	a, err := r.Lookup(ctx, "a.example.test")
	if err != nil || !slices.Equal(a.IPs, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("a: %+v %v", a, err)
	}
	c, _ := r.Lookup(ctx, "alias.example.test")
	if !c.Resolved() || !slices.Equal(c.CNAMEs, []string{"a.example.test"}) {
		t.Fatalf("alias: %+v", c)
	}
	n, err := r.Lookup(ctx, "missing.nowhere.test")
	if err != nil || n.Resolved() {
		t.Fatalf("nx: %+v %v", n, err)
	}
	if _, err := r.Lookup(ctx, "fail.example.test"); err == nil {
		t.Fatal("expected SERVFAIL error")
	}
}

func TestWildcard(t *testing.T) {
	r := New([]string{startServer(t)}, time.Second)
	ctx := context.Background()
	w, _ := r.Lookup(ctx, "anything.wild.example.test")
	if !r.IsWildcard(ctx, "anything.wild.example.test", w) {
		t.Fatal("expected wildcard")
	}
	a, _ := r.Lookup(ctx, "a.example.test")
	if r.IsWildcard(ctx, "a.example.test", a) {
		t.Fatal("unexpected wildcard")
	}
}

func TestPTR(t *testing.T) {
	r := New([]string{startServer(t)}, time.Second)
	got, err := r.PTR(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if err != nil || !slices.Equal(got, []string{"a.example.test"}) {
		t.Fatalf("ptr: %v %v", got, err)
	}
}
