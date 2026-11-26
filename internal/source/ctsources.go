package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/httpx"
)

// ---- SSLMate Cert Spotter (v1 issuances API) ----

type CertSpotter struct{ base }

func NewCertSpotter(c *httpx.Client, key string) *CertSpotter {
	every := 6 * time.Second // keyless: small hourly budget
	if key != "" {
		every = 200 * time.Millisecond
	}
	return &CertSpotter{base{
		info:    Info{Name: "certspotter", Kind: CT, Default: true, KeyName: "certspotter", Desc: "SSLMate Cert Spotter issuances API"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(every), 3),
		baseURL: "https://api.certspotter.com/v1/issuances",
	}}
}

func (s *CertSpotter) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	after := ""
	for page := 0; page < 200; page++ {
		q := url.Values{"domain": {domain}, "include_subdomains": {"true"}, "expand": {"dns_names"}}
		if after != "" {
			q.Set("after", after)
		}
		var rows []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if _, err := s.http.GetJSON(ctx, s.baseURL+"?"+q.Encode(), bearer(s.key), s.lim, &rows); err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, r := range rows {
			for _, n := range r.DNSNames {
				emit(n)
			}
		}
		after = rows[len(rows)-1].ID
	}
	return nil
}

// ---- ctlogs.dev ----

// CTLogs queries ctlogs.dev. Keyless access allows one request at a time, so
// calls are serialised.
type CTLogs struct {
	base
	mu sync.Mutex
}

func NewCTLogs(c *httpx.Client, key string) *CTLogs {
	every := time.Second
	if key != "" {
		every = 100 * time.Millisecond
	}
	return &CTLogs{base: base{
		info:    Info{Name: "ctlogs", Kind: CT, Default: true, KeyName: "ctlogs", Desc: "ctlogs.dev host index (current + 90 days)"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(every), 1),
		baseURL: "https://api.ctlogs.dev/v1",
	}}
}

func (s *CTLogs) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	return s.paged(ctx, s.baseURL+"/hosts/"+url.PathEscape(domain), func(raw json.RawMessage) error {
		var page struct {
			Hosts []struct {
				Host string `json:"host"`
			} `json:"hosts"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, h := range page.Hosts {
			emit(h.Host)
		}
		return nil
	})
}

// OrgSearch finds certificate names by subject organization (used by --org-pivot).
func (s *CTLogs) OrgSearch(ctx context.Context, org string, maxPages int, emit func(string)) error {
	return s.pagedN(ctx, s.baseURL+"/org?q="+url.QueryEscape(org), maxPages, func(raw json.RawMessage) error {
		var page struct {
			Rows []struct {
				SubjectCN string   `json:"subject_cn"`
				Domains   []string `json:"domains"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, r := range page.Rows {
			emit(r.SubjectCN)
			for _, d := range r.Domains {
				emit(d)
			}
		}
		return nil
	})
}

func (s *CTLogs) paged(ctx context.Context, u string, each func(json.RawMessage) error) error {
	return s.pagedN(ctx, u, 100, each)
}

func (s *CTLogs) pagedN(ctx context.Context, u string, maxPages int, each func(json.RawMessage) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cursor := ""
	for page := 0; page < maxPages; page++ {
		pu := u
		if cursor != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			pu += sep + "after=" + url.QueryEscape(cursor)
		}
		data, _, err := s.http.Do(ctx, httpx.Request{URL: pu, Header: bearer(s.key), Limiter: s.lim})
		if err != nil {
			if page > 0 && s.key == "" {
				return nil // keyless paging limit reached; keep what we have
			}
			return err
		}
		if err := each(data); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		var meta struct {
			HasNext    bool   `json:"has_next"`
			NextCursor string `json:"next_cursor"`
		}
		_ = json.Unmarshal(data, &meta)
		if !meta.HasNext || meta.NextCursor == "" {
			return nil
		}
		cursor = meta.NextCursor
	}
	return nil
}

// ---- Censys Platform API (v3) ----

type Censys struct {
	base
	org string
}

func NewCensys(c *httpx.Client, token, org string) *Censys {
	return &Censys{base: base{
		info:    Info{Name: "censys", Kind: CT, Default: true, KeyName: "censys", KeyRequired: true, Desc: "Censys Platform certificate search (personal access token)"},
		key:     token,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(time.Second), 1),
		baseURL: "https://api.platform.censys.io/v3/global/search/query",
	}, org: org}
}

func (s *Censys) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	u := s.baseURL
	if s.org != "" {
		u += "?organization_id=" + url.QueryEscape(s.org)
	}
	token := ""
	// Each page costs credits; 10 pages = up to 1000 certificates.
	for page := 0; page < 10; page++ {
		body := map[string]any{"query": fmt.Sprintf("cert.names: %q", domain), "page_size": 100}
		if token != "" {
			body["page_token"] = token
		}
		b, _ := json.Marshal(body)
		data, _, err := s.http.Do(ctx, httpx.Request{Method: "POST", URL: u, Header: bearer(s.key), Body: b, Limiter: s.lim})
		if err != nil {
			return err
		}
		var resp struct {
			Result struct {
				Hits []struct {
					Cert *struct {
						Resource struct {
							Names []string `json:"names"`
						} `json:"resource"`
					} `json:"certificate_v1"`
				} `json:"hits"`
				NextPageToken string `json:"next_page_token"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		for _, h := range resp.Result.Hits {
			if h.Cert != nil {
				for _, n := range h.Cert.Resource.Names {
					emit(n)
				}
			}
		}
		if resp.Result.NextPageToken == "" || len(resp.Result.Hits) == 0 {
			return nil
		}
		token = resp.Result.NextPageToken
	}
	return nil
}

// ---- Merklemap ----

type Merklemap struct{ base }

func NewMerklemap(c *httpx.Client, key string) *Merklemap {
	return &Merklemap{base{
		info:    Info{Name: "merklemap", Kind: CT, Default: true, KeyName: "merklemap", KeyRequired: true, Desc: "Merklemap CT hostname search (paid API token)"},
		key:     key,
		http:    c,
		lim:     rate.NewLimiter(rate.Every(250*time.Millisecond), 2),
		baseURL: "https://api.merklemap.com/v1/search",
	}}
}

func (s *Merklemap) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	for page := 0; page < 100; page++ {
		q := url.Values{"query": {"*." + domain}, "type": {"wildcard"}, "page": {fmt.Sprint(page)}}
		var resp struct {
			Count   int `json:"count"`
			Results []struct {
				Hostname string `json:"hostname"`
				CN       string `json:"subject_common_name"`
			} `json:"results"`
		}
		if _, err := s.http.GetJSON(ctx, s.baseURL+"?"+q.Encode(), bearer(s.key), s.lim, &resp); err != nil {
			return err
		}
		for _, r := range resp.Results {
			emit(r.Hostname)
			emit(r.CN)
		}
		if len(resp.Results) == 0 {
			return nil
		}
	}
	return nil
}
