package source

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/httpx"
)

// ---- VirusTotal (API v3) ----

type VirusTotal struct{ base }

func NewVirusTotal(c *httpx.Client, key string) *VirusTotal {
	// The free tier allows 4 requests/minute; one limiter is shared by the
	// domain and IP lookups so the IP sweep can't starve or trip the quota.
	return &VirusTotal{base{
		info:    Info{Name: "virustotal", Kind: PDNS, Default: true, KeyName: "virustotal", KeyRequired: true, Desc: "VirusTotal v3 subdomains / IP resolutions"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(15*time.Second), 4),
		baseURL: "https://www.virustotal.com/api/v3",
	}}
}

type vtPage struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			HostName string `json:"host_name"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (s *VirusTotal) walk(ctx context.Context, u string, maxPages int, each func(vtPage)) error {
	for page := 0; page < maxPages && u != ""; page++ {
		var p vtPage
		if _, err := s.http.GetJSON(ctx, u, header("x-apikey", s.key), s.lim, &p); err != nil {
			return err
		}
		each(p)
		u = p.Links.Next
	}
	return nil
}

func (s *VirusTotal) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	return s.walk(ctx, s.baseURL+"/domains/"+url.PathEscape(domain)+"/subdomains?limit=40", 25, func(p vtPage) {
		for _, d := range p.Data {
			emit(d.ID)
		}
	})
}

// IPResolutions returns hostnames VirusTotal has seen resolving to addr.
func (s *VirusTotal) IPResolutions(ctx context.Context, addr netip.Addr, emit func(string)) error {
	return s.walk(ctx, s.baseURL+"/ip_addresses/"+addr.String()+"/resolutions?limit=40", 5, func(p vtPage) {
		for _, d := range p.Data {
			emit(d.Attributes.HostName)
		}
	})
}

// ---- HackerTarget ----

type HackerTarget struct{ base }

func NewHackerTarget(c *httpx.Client, key string) *HackerTarget {
	return &HackerTarget{base{
		info:    Info{Name: "hackertarget", Kind: PDNS, Default: true, KeyName: "hackertarget", Desc: "HackerTarget hostsearch (20/day keyless)"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(time.Second), 1),
		baseURL: "https://api.hackertarget.com/hostsearch/",
	}}
}

func (s *HackerTarget) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	q := url.Values{"q": {domain}}
	if s.key != "" {
		q.Set("apikey", s.key)
	}
	data, _, err := s.http.Do(ctx, httpx.Request{URL: s.baseURL + "?" + q.Encode(), Header: header("Accept", "text/plain"), Limiter: s.lim})
	if err != nil {
		return err
	}
	body := strings.TrimSpace(string(data))
	low := strings.ToLower(body)
	switch {
	case strings.Contains(low, "api count exceeded"):
		return fmt.Errorf("%w: %s", httpx.ErrRateLimited, firstLine(body))
	case strings.HasPrefix(low, "error"):
		return errors.New(firstLine(body))
	case strings.HasPrefix(low, "no records found"):
		return nil
	}
	for _, line := range strings.Split(body, "\n") {
		host, _, _ := strings.Cut(line, ",")
		emit(host)
	}
	return nil
}

// ---- AlienVault OTX ----

type OTX struct{ base }

func NewOTX(c *httpx.Client, key string) *OTX {
	return &OTX{base{
		info:    Info{Name: "otx", Kind: PDNS, Default: true, KeyName: "otx", Desc: "AlienVault OTX passive DNS (free key recommended)"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(time.Second), 1),
		baseURL: "https://otx.alienvault.com/api/v1/indicators/domain/",
	}}
}

func (s *OTX) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if _, err := s.http.GetJSON(ctx, s.baseURL+url.PathEscape(domain)+"/passive_dns", header("X-OTX-API-KEY", s.key), s.lim, &resp); err != nil {
		return err
	}
	for _, r := range resp.PassiveDNS {
		emit(r.Hostname)
	}
	return nil
}

// ---- urlscan.io ----

type URLScan struct{ base }

func NewURLScan(c *httpx.Client, key string) *URLScan {
	return &URLScan{base{
		info:    Info{Name: "urlscan", Kind: PDNS, Default: true, KeyName: "urlscan", Desc: "urlscan.io search (domains seen in scans)"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(2*time.Second), 1),
		baseURL: "https://urlscan.io/api/v1/search/",
	}}
}

func (s *URLScan) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	searchAfter := ""
	pages := 10
	if s.key != "" {
		pages = 50
	}
	for page := 0; page < pages; page++ {
		q := url.Values{"q": {"domain:" + domain}, "size": {"100"}}
		if searchAfter != "" {
			q.Set("search_after", searchAfter)
		}
		var resp struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
				Task struct {
					Domain string `json:"domain"`
				} `json:"task"`
				Sort []any `json:"sort"`
			} `json:"results"`
			HasMore bool `json:"has_more"`
		}
		if _, err := s.http.GetJSON(ctx, s.baseURL+"?"+q.Encode(), header("API-Key", s.key), s.lim, &resp); err != nil {
			if page > 0 {
				return nil
			}
			return err
		}
		for _, r := range resp.Results {
			emit(r.Page.Domain)
			emit(r.Task.Domain)
		}
		if !resp.HasMore || len(resp.Results) == 0 {
			return nil
		}
		var parts []string
		for _, v := range resp.Results[len(resp.Results)-1].Sort {
			parts = append(parts, fmt.Sprint(v))
		}
		searchAfter = strings.Join(parts, ",")
	}
	return nil
}

// ---- RapidDNS (HTML scrape; opt-in because the markup can change) ----

type RapidDNS struct{ base }

func NewRapidDNS(c *httpx.Client) *RapidDNS {
	return &RapidDNS{base{
		info:    Info{Name: "rapiddns", Kind: PDNS, Desc: "RapidDNS subdomain page (HTML scrape, opt-in)"},
		http:    c,
		lim:     rate.NewLimiter(rate.Every(2*time.Second), 1),
		baseURL: "https://rapiddns.io/subdomain/",
	}}
}

func (s *RapidDNS) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	h := http.Header{"Accept": {"text/html"}}
	data, _, err := s.http.Do(ctx, httpx.Request{URL: s.baseURL + url.PathEscape(domain) + "?full=1", Header: h, Limiter: s.lim})
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?i)[a-z0-9_*][a-z0-9_.-]*\.` + regexp.QuoteMeta(domain) + `\b`)
	for _, m := range re.FindAllString(string(data), -1) {
		emit(m)
	}
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}
