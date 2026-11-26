package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errb bytes.Buffer
	code := run(args, nil, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionAndListSources(t *testing.T) {
	if code, out, _ := runCLI(t, "--version"); code != 0 || !strings.Contains(out, version) {
		t.Fatalf("version: %d %q", code, out)
	}
	code, out, _ := runCLI(t, "--list-sources")
	if code != 0 || !strings.Contains(out, "crtsh-db") || !strings.Contains(out, "required (missing)") {
		t.Fatalf("list: %d\n%s", code, out)
	}
}

func TestValidation(t *testing.T) {
	cases := [][]string{
		{},                                  // nothing to do
		{"-d", "bad_domain..com"},           // invalid domain
		{"-d", "example.com", "-f", "xml"},  // bad format
		{"-d", "example.com", "-s", "nope"}, // unknown source
		{"-i", "10.0.0.0/8"},                // too big without --force
		{"-i", "10.0.0.0/24", "-p", "0"},    // bad port
		{"-i", "10.0.0.0/24", "-V"},         // VirusTotal without key
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestCollectDomainsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.txt")
	os.WriteFile(p, []byte("# comment\nExample.com\n\nexample.org,example.com\n"), 0o600)
	got, err := collectDomains(flags{domainFile: []string{p}, domains: []string{"https://example.net/"}}, nil)
	if err != nil || strings.Join(got, " ") != "example.net example.com example.org" {
		t.Fatalf("got %v %v", got, err)
	}
}
