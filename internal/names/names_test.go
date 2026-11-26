package names

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"WWW.Example.COM", "www.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.*.example.com", "example.com", true},
		{" api.example.com. ", "api.example.com", true},
		{"_svc.internal.example.com", "_svc.internal.example.com", true},
		{"admin@example.com", "", false},
		{"10.0.0.1", "", false},
		{"2001:db8::1", "", false},
		{"localhost", "", false},
		{"https://example.com", "", false},
		{"bad-.example.com", "", false},
		{"-bad.example.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Normalize(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	if d, ok := NormalizeDomain("https://Example.com/path"); !ok || d != "example.com" {
		t.Fatalf("got %q %v", d, ok)
	}
}

func TestInScope(t *testing.T) {
	if !InScope("example.com", "example.com") || !InScope("a.b.example.com", "example.com") {
		t.Fatal("expected in scope")
	}
	if InScope("notexample.com", "example.com") || InScope("example.com.evil.net", "example.com") {
		t.Fatal("expected out of scope")
	}
}

func TestApex(t *testing.T) {
	if a := Apex("a.b.example.co.uk"); a != "example.co.uk" {
		t.Fatalf("got %q", a)
	}
}
