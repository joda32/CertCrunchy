package certscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"
)

// selfSigned builds the kind of certificate the Python version silently
// dropped: self-signed and, optionally, expired.
func selfSigned(t *testing.T, cn string, dns []string, org string, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if expired {
		nb, na = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		DNSNames:     dns,
		NotBefore:    nb,
		NotAfter:     na,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS starts a TLS listener on 127.0.0.1 and returns its port.
func serveTLS(t *testing.T, cfg *tls.Config) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var loopback = netip.MustParseAddr("127.0.0.1")

func TestGrabSelfSignedExpired(t *testing.T) {
	cert := selfSigned(t, "appliance.corp.example", []string{"*.lab.corp.example", "mgmt.corp.example"}, "Acme Pty Ltd", true)
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})

	s := &Scanner{Timeout: time.Second}
	sg, err := s.Grab(context.Background(), Target{Addr: loopback, Port: port})
	if err != nil {
		t.Fatalf("grab: %v", err)
	}
	want := []string{"appliance.corp.example", "lab.corp.example", "mgmt.corp.example"}
	if !slices.Equal(sg.Names, want) {
		t.Fatalf("names = %v, want %v", sg.Names, want)
	}
	if !sg.SelfSigned || !sg.Expired || sg.Organization[0] != "Acme Pty Ltd" {
		t.Fatalf("metadata wrong: %+v", sg)
	}
}

func TestDescribeAllSANTypes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u1, _ := url.Parse("https://portal.corp.example:8443/login")
	u2, _ := url.Parse("spiffe://Mesh.Corp.Example/ns/default")
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(7),
		Subject:        pkix.Name{CommonName: "10.1.2.3"},
		DNSNames:       []string{"www.corp.example"},
		EmailAddresses: []string{"admin@mail.corp.example", "not-an-email"},
		URIs:           []*url.URL{u1, u2},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::5"), net.ParseIP("10.1.2.3")},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	sg := describe(Target{Addr: loopback, Port: 443}, c)

	wantNames := []string{"mail.corp.example", "mesh.corp.example", "portal.corp.example", "www.corp.example"}
	if !slices.Equal(sg.Names, wantNames) {
		t.Fatalf("names = %v, want %v", sg.Names, wantNames)
	}
	wantIPs := []string{"10.1.2.3", "192.0.2.10", "2001:db8::5"}
	if !slices.Equal(sg.IPSANs, wantIPs) {
		t.Fatalf("ip sans = %v, want %v", sg.IPSANs, wantIPs)
	}
}

func TestGrabSurvivesClientCertRequirement(t *testing.T) {
	cert := selfSigned(t, "mtls.corp.example", nil, "Acme", false)
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert})

	sg, err := (&Scanner{Timeout: time.Second}).Grab(context.Background(), Target{Addr: loopback, Port: port})
	if err != nil {
		t.Fatalf("grab: %v", err)
	}
	if !slices.Contains(sg.Names, "mtls.corp.example") {
		t.Fatalf("names = %v", sg.Names)
	}
}

func TestGrabUsesSNI(t *testing.T) {
	def := selfSigned(t, "default.example", nil, "x", false)
	vhost := selfSigned(t, "vhost.example", nil, "x", false)
	port := serveTLS(t, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "vhost.example" {
			return &vhost, nil
		}
		return &def, nil
	}})
	s := &Scanner{Timeout: time.Second}
	a, _ := s.Grab(context.Background(), Target{Addr: loopback, Port: port})
	b, _ := s.Grab(context.Background(), Target{Addr: loopback, Port: port, SNI: "vhost.example"})
	if a == nil || b == nil || a.CommonName != "default.example" || b.CommonName != "vhost.example" {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
}

func TestGrabClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := (&Scanner{Timeout: 500 * time.Millisecond}).Grab(context.Background(), Target{Addr: loopback, Port: port}); err == nil {
		t.Fatal("expected error")
	}
}

func TestScanMultiPort(t *testing.T) {
	p1 := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "one.example", nil, "x", false)}})
	p2 := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "two.example", nil, "x", false)}})
	r, err := ParseRanges([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ports, err := ParsePorts([]string{strconv.Itoa(p1) + "," + strconv.Itoa(p2)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	(&Scanner{Timeout: time.Second, Concurrency: 4}).Scan(context.Background(), r.Targets(ports),
		func(s *Sighting) { got = append(got, s.Names...) }, nil)
	slices.Sort(got)
	if !slices.Equal(got, []string{"one.example", "two.example"}) {
		t.Fatalf("got %v", got)
	}
}

func TestParseRanges(t *testing.T) {
	r, err := ParseRanges([]string{"10.0.0.7/30,192.0.2.1", "2001:db8::/126"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Size.Int64() != 4+1+4 {
		t.Fatalf("size = %v", r.Size)
	}
	var n int
	for range r.Addrs() {
		n++
	}
	if n != 9 {
		t.Fatalf("addrs = %d", n)
	}
	if !r.Contains(netip.MustParseAddr("10.0.0.5")) || r.Contains(netip.MustParseAddr("10.0.0.8")) {
		t.Fatal("contains wrong")
	}
	if _, err := ParseRanges([]string{"nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePorts(t *testing.T) {
	ps, err := ParsePorts([]string{"443,web,8443"})
	if err != nil || ps[0] != 443 || len(ps) != 5 {
		t.Fatalf("ports=%v err=%v", ps, err)
	}
	if _, err := ParsePorts([]string{"70000"}); err == nil {
		t.Fatal("expected error")
	}
}
