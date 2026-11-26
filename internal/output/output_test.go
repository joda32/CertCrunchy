package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/joda32/certcrunchy/internal/pipeline"
)

func sample() *pipeline.Result {
	return &pipeline.Result{
		Hosts: []*pipeline.Host{
			{Name: "a.example.com", Resolved: true, IPs: []string{"192.0.2.1", "2001:db8::1"}, Sources: []string{"crtsh-db", "certspotter"}},
			{Name: "b.example.com", Sources: []string{"certscan"}},
		},
		Health: []pipeline.Health{
			{Source: "crtsh-db", Target: "example.com", Status: pipeline.StatusOK, Count: 2},
			{Source: "ctlogs", Target: "example.com", Status: pipeline.StatusRateLimited, Error: "rate limited"},
		},
	}
}

func TestCSV(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Options{Format: "csv"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 || lines[1] != "a.example.com,true,false,false,192.0.2.1;2001:db8::1,,crtsh-db;certspotter" {
		t.Fatalf("csv:\n%s", b.String())
	}
}

func TestResolvedOnlyAndJSONL(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Options{Format: "jsonl", ResolvedOnly: true}); err != nil {
		t.Fatal(err)
	}
	var h pipeline.Host
	if err := json.Unmarshal(b.Bytes(), &h); err != nil || h.Name != "a.example.com" || strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("jsonl: %s (%v)", b.String(), err)
	}
}

func TestJSONEnvelope(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Options{Format: "json", Version: "t", Targets: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hosts  []map[string]any `json:"hosts"`
		Health []map[string]any `json:"health"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil || len(doc.Hosts) != 2 || len(doc.Health) != 2 {
		t.Fatalf("json: %v %s", err, b.String())
	}
}

func TestTextAndSummary(t *testing.T) {
	var b bytes.Buffer
	_ = Write(&b, sample(), Options{Format: "text"})
	if !strings.Contains(b.String(), "a.example.com") || !strings.Contains(b.String(), "b.example.com  -") {
		t.Fatalf("text:\n%s", b.String())
	}
	b.Reset()
	Summary(&b, sample(), false)
	if !strings.Contains(b.String(), "example.com: rate-limited") || !strings.Contains(b.String(), "2 unique names, 1 resolving") {
		t.Fatalf("summary:\n%s", b.String())
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, sample(), Options{Format: "xml"}); err == nil {
		t.Fatal("expected error")
	}
}
