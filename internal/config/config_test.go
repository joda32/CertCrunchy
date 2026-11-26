package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndEnvOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("keys:\n  certspotter: filekey\n  censys-org: org1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Key("certspotter") != "filekey" || c.Key("censys-org") != "org1" || c.Key("otx") != "" {
		t.Fatalf("keys = %+v", c.Keys)
	}
	t.Setenv("CERTCRUNCHY_CERTSPOTTER_KEY", "envkey")
	t.Setenv("CERTCRUNCHY_CENSYS_ORG_KEY", "org2")
	if c.Key("certspotter") != "envkey" || c.Key("censys-org") != "org2" {
		t.Fatal("env must override file")
	}
}

func TestMissingFiles(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("explicit missing file must error")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if c, err := Load(""); err != nil || c.Path != "" {
		t.Fatalf("default missing file must be fine: %v %+v", err, c)
	}
}
