package source

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/httpx"
)

func testClient() *httpx.Client {
	c := httpx.New(5*time.Second, "test")
	c.BaseBackof = time.Millisecond
	return c
}

// fixture serves canned responses keyed by "METHOD path?query" prefix.
func fixture(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		// Longest matching prefix wins.
		best := ""
		for k := range routes {
			if strings.HasPrefix(key, k) && len(k) > len(best) {
				best = k
			}
		}
		if best == "" {
			t.Errorf("unexpected request %s", key)
			http.NotFound(w, r)
			return
		}
		routes[best](w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func text(s string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, s) }
}

func collect(t *testing.T, s Source, domain string) ([]string, error) {
	t.Helper()
	var got []string
	err := s.Enumerate(context.Background(), domain, func(n string) { got = append(got, n) })
	slices.Sort(got)
	return slices.Compact(got), err
}

func fast(b *base) { b.lim = rate.NewLimiter(rate.Inf, 1) }

func TestCrtshHTTP(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /?q=%25.example.com": text(`[{"name_value":"a.example.com\n*.b.example.com","common_name":"a.example.com"}]`),
	})
	s := NewCrtshHTTP(testClient())
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"*.b.example.com", "a.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
	if s.Info().FallbackFor != "crtsh-db" {
		t.Fatal("crtsh must be the crtsh-db fallback")
	}
}

func TestCertSpotterPaging(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /?domain=example.com&expand=dns_names&include_subdomains=true":         text(`[{"id":"1","dns_names":["a.example.com"]},{"id":"2","dns_names":["b.example.com"]}]`),
		"GET /?after=2&domain=example.com&expand=dns_names&include_subdomains=true": text(`[{"id":"3","dns_names":["c.example.com"]}]`),
		"GET /?after=3&domain=example.com&expand=dns_names&include_subdomains=true": text(`[]`),
	})
	s := NewCertSpotter(testClient(), "")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestCTLogsPagingAndKeylessLimit(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /v1/hosts/example.com": text(`{"hosts":[{"host":"*.a.example.com"}],"has_next":true,"next_cursor":"c1"}`),
		"GET /v1/hosts/example.com?after=c1": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"paging needs a key"}`, http.StatusForbidden)
		},
	})
	s := NewCTLogs(testClient(), "")
	s.baseURL = u + "/v1"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"*.a.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestCTLogsOrgSearch(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /v1/org?q=Acme+Pty": text(`{"rows":[{"subject_cn":"acme.example","domains":["www.acme.example","acme-corp.example"]}],"has_next":false,"next_cursor":""}`),
	})
	s := NewCTLogs(testClient(), "")
	s.baseURL = u + "/v1"
	fast(&s.base)
	var got []string
	if err := s.OrgSearch(context.Background(), "Acme Pty", 3, func(n string) { got = append(got, n) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestCensys(t *testing.T) {
	var bodies []string
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("organization_id") != "org1" {
				t.Errorf("bad auth/org: %v %v", r.Header, r.URL)
			}
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			if strings.Contains(string(b), "page_token") {
				io.WriteString(w, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["c.example.com"]}}}],"next_page_token":""}}`)
				return
			}
			io.WriteString(w, `{"result":{"hits":[{"certificate_v1":{"resource":{"names":["a.example.com","*.b.example.com"]}}}],"next_page_token":"p2"}}`)
		},
	})
	s := NewCensys(testClient(), "tok", "org1")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || len(got) != 3 || !strings.Contains(bodies[0], `cert.names: \"example.com\"`) {
		t.Fatalf("got %v err %v bodies %v", got, err, bodies)
	}
	if NewCensys(nil, "", "").Info().Usable() {
		t.Fatal("censys without token must be unusable")
	}
}

func TestMerklemap(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /?page=0": text(`{"count":2,"results":[{"hostname":"a.example.com","subject_common_name":"a.example.com"},{"hostname":"b.example.com"}]}`),
		"GET /?page=1": text(`{"count":2,"results":[]}`),
	})
	s := NewMerklemap(testClient(), "k")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Contains(got, "b.example.com") {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestVirusTotal(t *testing.T) {
	var base string
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com/subdomains?limit=40": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("x-apikey") != "k" {
				t.Error("missing key")
			}
			io.WriteString(w, `{"data":[{"id":"a.example.com"}],"links":{"next":"`+base+`/domains/example.com/subdomains?cursor=x"}}`)
		},
		"GET /domains/example.com/subdomains?cursor=x": text(`{"data":[{"id":"b.example.com"}],"links":{}}`),
		"GET /ip_addresses/192.0.2.1/resolutions":      text(`{"data":[{"attributes":{"host_name":"c.example.com"}}],"links":{}}`),
	})
	base = u
	s := NewVirusTotal(testClient(), "k")
	s.baseURL = u
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
	var ipNames []string
	if err := s.IPResolutions(context.Background(), netip.MustParseAddr("192.0.2.1"), func(n string) { ipNames = append(ipNames, n) }); err != nil || len(ipNames) != 1 {
		t.Fatalf("ip: %v %v", ipNames, err)
	}
}

func TestHackerTarget(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /?q=example.com": text("a.example.com,192.0.2.1\nb.example.com,192.0.2.2\n"),
		"GET /?q=busy.com":    text("API count exceeded - Increase Quota with Membership"),
	})
	s := NewHackerTarget(testClient(), "")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
	if _, err := collect(t, s, "busy.com"); !errors.Is(err, httpx.ErrRateLimited) {
		t.Fatalf("want rate limited, got %v", err)
	}
}

func TestOTX(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /example.com/passive_dns": text(`{"passive_dns":[{"hostname":"a.example.com"},{"hostname":"other.net"}]}`),
	})
	s := NewOTX(testClient(), "")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestURLScanPaging(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /?q=domain%3Aexample.com&search_after=": text(`{"results":[{"page":{"domain":"c.example.com"},"task":{"domain":"c.example.com"},"sort":[2,"y"]}],"has_more":false}`),
		"GET /?q=domain%3Aexample.com&size=100":      text(`{"results":[{"page":{"domain":"a.example.com"},"task":{"domain":"b.example.com"},"sort":[1,"x"]}],"has_more":true}`),
	})
	s := NewURLScan(testClient(), "")
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestRapidDNS(t *testing.T) {
	u := fixture(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /example.com": text(`<table><tr><td>a.example.com</td><td>x.notexample.community</td><td>B.Example.com</td></tr></table>`),
	})
	s := NewRapidDNS(testClient())
	s.baseURL = u + "/"
	fast(&s.base)
	got, err := collect(t, s, "example.com")
	if err != nil || !slices.Equal(got, []string{"B.Example.com", "a.example.com"}) {
		t.Fatalf("got %v err %v", got, err)
	}
	if s.Info().Default {
		t.Fatal("rapiddns must be opt-in")
	}
}
