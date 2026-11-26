// Package config loads API keys from a YAML file and environment variables.
//
// File (default: $XDG_CONFIG_HOME/certcrunchy/config.yaml):
//
//	keys:
//	  certspotter: "..."
//	  censys: "personal-access-token"
//	  censys-org: "organization-id"   # optional
//
// Environment variables override the file: CERTCRUNCHY_<NAME>_KEY, where NAME
// is the key name upper-cased with '-' replaced by '_' (CERTCRUNCHY_CENSYS_ORG_KEY).
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Keys map[string]string `yaml:"keys"`
	Path string            `yaml:"-"`
}

// DefaultPath returns the default config file location.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "certcrunchy", "config.yaml")
}

// Load reads path (or the default path when empty). A missing default file is
// not an error; a missing explicitly-named file is.
func Load(path string) (*Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultPath()
	}
	cfg := &Config{Keys: map[string]string{}, Path: path}
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(b, cfg); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			if cfg.Keys == nil {
				cfg.Keys = map[string]string{}
			}
		case errors.Is(err, fs.ErrNotExist) && !explicit:
			cfg.Path = ""
		default:
			return nil, err
		}
	}
	return cfg, nil
}

// Key returns the value for name, preferring the environment.
func (c *Config) Key(name string) string {
	env := "CERTCRUNCHY_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_KEY"
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.Keys[name])
}
