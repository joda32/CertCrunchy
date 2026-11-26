// Package output renders results as text, CSV, JSON or JSON Lines.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/joda32/certcrunchy/internal/pipeline"
)

var Formats = []string{"text", "csv", "json", "jsonl"}

type Options struct {
	Format       string
	ResolvedOnly bool
	Color        bool
	Version      string
	Targets      []string
}

// Filter applies ResolvedOnly.
func Filter(hosts []*pipeline.Host, resolvedOnly bool) []*pipeline.Host {
	if !resolvedOnly {
		return hosts
	}
	var out []*pipeline.Host
	for _, h := range hosts {
		if h.Resolved {
			out = append(out, h)
		}
	}
	return out
}

func Write(w io.Writer, res *pipeline.Result, o Options) error {
	hosts := Filter(res.Hosts, o.ResolvedOnly)
	switch o.Format {
	case "", "text":
		return writeText(w, hosts, o.Color)
	case "csv":
		return writeCSV(w, hosts)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if hosts == nil {
			hosts = []*pipeline.Host{}
		}
		return enc.Encode(struct {
			Tool      string            `json:"tool"`
			Generated time.Time         `json:"generated"`
			Targets   []string          `json:"targets"`
			Hosts     []*pipeline.Host  `json:"hosts"`
			Health    []pipeline.Health `json:"health"`
		}{"certcrunchy " + o.Version, time.Now().UTC(), o.Targets, hosts, res.Health})
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, h := range hosts {
			if err := enc.Encode(h); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want %s)", o.Format, strings.Join(Formats, ", "))
	}
}

// Names writes bare hostnames, one per line (for --silent piping).
func Names(w io.Writer, res *pipeline.Result, resolvedOnly bool) error {
	for _, h := range Filter(res.Hosts, resolvedOnly) {
		if _, err := fmt.Fprintln(w, h.Name); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV(w io.Writer, hosts []*pipeline.Host) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "resolved", "wildcard", "in_range", "ips", "cnames", "sources"})
	for _, h := range hosts {
		_ = cw.Write([]string{
			h.Name, fmt.Sprint(h.Resolved), fmt.Sprint(h.Wildcard), fmt.Sprint(h.InRange),
			strings.Join(h.IPs, ";"), strings.Join(h.CNAMEs, ";"), strings.Join(h.Sources, ";"),
		})
	}
	cw.Flush()
	return cw.Error()
}

const (
	cReset = "\033[0m"
	cGreen = "\033[32m"
	cDim   = "\033[90m"
	cYel   = "\033[33m"
)

func writeText(w io.Writer, hosts []*pipeline.Host, color bool) error {
	paint := func(c, s string) string {
		if !color {
			return s
		}
		return c + s + cReset
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, h := range hosts {
		addr := strings.Join(h.IPs, ", ")
		name := h.Name
		switch {
		case h.Wildcard:
			name = paint(cYel, name)
			addr += " (wildcard)"
		case h.Resolved:
			name = paint(cGreen, name)
		default:
			name = paint(cDim, name)
			addr = "-"
		}
		if len(h.CNAMEs) > 0 {
			addr += "  (cname " + strings.Join(h.CNAMEs, " → ") + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, addr, paint(cDim, "["+strings.Join(h.Sources, ",")+"]"))
	}
	return tw.Flush()
}

// Summary writes a per-source health table and totals (to stderr normally).
func Summary(w io.Writer, res *pipeline.Result, color bool) {
	type agg struct {
		ok, fail int
		count    int
		dur      time.Duration
		errs     []string
	}
	by := map[string]*agg{}
	var order []string
	for _, h := range res.Health {
		a := by[h.Source]
		if a == nil {
			a = &agg{}
			by[h.Source] = a
			order = append(order, h.Source)
		}
		a.count += h.Count
		a.dur += h.Duration
		switch h.Status {
		case pipeline.StatusOK, pipeline.StatusEmpty:
			a.ok++
		case pipeline.StatusPartial:
			a.ok++
			a.errs = append(a.errs, fmt.Sprintf("%s: partial", h.Target))
		default:
			a.fail++
			a.errs = append(a.errs, fmt.Sprintf("%s: %s", h.Target, h.Status))
		}
	}
	sort.Strings(order)
	resolved, wild := 0, 0
	for _, h := range res.Hosts {
		if h.Resolved {
			resolved++
		}
		if h.Wildcard {
			wild++
		}
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tOK\tFAILED\tNAMES\tTIME\tNOTES")
	for _, s := range order {
		a := by[s]
		note := ""
		if len(a.errs) > 0 {
			note = strings.Join(a.errs, "; ")
			if len(note) > 70 {
				note = note[:69] + "…"
			}
			if color {
				note = cYel + note + cReset
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", s, a.ok, a.fail, a.count, a.dur.Round(10*time.Millisecond), note)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d unique names, %d resolving", len(res.Hosts), resolved)
	if wild > 0 {
		fmt.Fprintf(w, " (%d via wildcard DNS)", wild)
	}
	fmt.Fprintln(w)
}
