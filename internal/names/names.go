// Package names normalises and scopes hostnames collected from certificates
// and passive DNS sources.
package names

import (
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Underscores are tolerated because internal and service certificates use them.
var labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Normalize lowercases a raw name, strips a leading wildcard label and trailing
// dot, and reports whether the result is a plausible multi-label hostname.
// IP addresses, e-mail addresses, URLs and single-label names are rejected.
func Normalize(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	for strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "@/: *\t") {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", false
		}
	}
	return s, true
}

// NormalizeDomain cleans a user-supplied target domain.
func NormalizeDomain(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return Normalize(s)
}

// InScope reports whether name equals domain or is a subdomain of it.
func InScope(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// Apex returns the registrable domain (eTLD+1) for name, or "" if it has none.
func Apex(name string) string {
	a, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return a
}
