// Command certcrunchy finds hostnames for domains and netblocks using
// Certificate Transparency, passive DNS and live TLS certificates.

// Old and broken certificates are exactly what netblock recon runs into, so
// accept negative serial numbers rather than dropping those certs.
//
//go:debug x509negativeserial=1
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/certscan"
	"github.com/joda32/certcrunchy/internal/config"
	"github.com/joda32/certcrunchy/internal/httpx"
	"github.com/joda32/certcrunchy/internal/logx"
	"github.com/joda32/certcrunchy/internal/names"
	"github.com/joda32/certcrunchy/internal/output"
	"github.com/joda32/certcrunchy/internal/pipeline"
	"github.com/joda32/certcrunchy/internal/resolve"
	"github.com/joda32/certcrunchy/internal/source"
)

var version = "2.0.0-dev"

const banner = "\033[1;33m" + `
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
` + "\033[1;31m" + "Just a silly recon tool...  @_w_m__  v%s" + "\033[0m\n\n"

const (
	maxRange   = 65536 // /16, as before; --force to exceed
	maxVTRange = 256   // VirusTotal free tier: 4 lookups/minute
)

type flags struct {
	domains, domainFile                   []string
	ranges, ports                         []string
	output, format                        string
	threads, scanThreads, scanRate, delay int
	requestTimeout                        int
	connectTimeout, sourceTimeout         time.Duration
	sources, exclude, resolvers           []string
	allSources, listSources               bool
	virustotal, noPTR, sni                bool
	pivot, orgPivot                       bool
	pivotMax, orgPivotMax                 int
	resolvedOnly, noResolve, force        bool
	configPath                            string
	silent, verbose, noColor, showVersion bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var f flags
	fs := flag.NewFlagSet("certcrunchy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.SortFlags = false
	fs.StringSliceVarP(&f.domains, "domain", "d", nil, "domain(s) to enumerate (repeatable, comma-separated)")
	fs.StringSliceVarP(&f.domainFile, "domains", "D", nil, "file with one domain per line ('-' for stdin)")
	fs.StringSliceVarP(&f.ranges, "iprange", "i", nil, "IP range(s) to sweep for certificates, e.g. 10.0.0.0/24, 2001:db8::/120, 192.0.2.7")
	fs.StringSliceVarP(&f.ports, "port", "p", []string{"443"}, "TLS port(s) for the sweep; presets: web, mail, all")
	fs.StringVarP(&f.output, "output", "o", "", "write results to this file")
	fs.StringVarP(&f.format, "format", "f", "", "output format: text, csv, json, jsonl (default text; csv for -o)")
	fs.StringSliceVarP(&f.sources, "sources", "s", nil, "only use these passive sources (see --list-sources)")
	fs.StringSliceVarP(&f.exclude, "exclude-sources", "x", nil, "skip these passive sources")
	fs.BoolVar(&f.allSources, "all-sources", false, "also use opt-in sources (e.g. rapiddns)")
	fs.BoolVar(&f.listSources, "list-sources", false, "list passive sources and key status, then exit")
	fs.BoolVarP(&f.virustotal, "virustotal", "V", false, "also ask VirusTotal for hostnames per IP in the range (slow: 4 IPs/min on a free key)")
	fs.BoolVar(&f.noPTR, "no-ptr", false, "skip reverse DNS for the IP range")
	fs.BoolVar(&f.sni, "sni", false, "re-probe in-range hosts with SNI to reveal non-default vhost certificates")
	fs.BoolVar(&f.pivot, "pivot", false, "query passive sources for new domains seen in netblock certificates")
	fs.IntVar(&f.pivotMax, "pivot-max", 10, "max domains to pivot into")
	fs.BoolVar(&f.orgPivot, "org-pivot", false, "search CT (ctlogs.dev) for certificates of organisations seen in netblock certificates")
	fs.IntVar(&f.orgPivotMax, "org-pivot-max", 5, "max organisations to pivot into")
	fs.StringSliceVarP(&f.resolvers, "resolvers", "r", nil, "DNS resolvers (ip[:port]); default: system resolvers")
	fs.BoolVar(&f.resolvedOnly, "resolved-only", false, "only report names that resolve (the v1 behaviour)")
	fs.BoolVar(&f.noResolve, "no-resolve", false, "skip DNS validation entirely")
	fs.IntVarP(&f.threads, "threads", "T", 50, "DNS/PTR concurrency")
	fs.IntVar(&f.scanThreads, "scan-threads", 200, "concurrent TLS connections during the sweep")
	fs.IntVar(&f.scanRate, "scan-rate", 0, "max new TLS connections per second (0 = unlimited)")
	fs.DurationVar(&f.connectTimeout, "connect-timeout", 2*time.Second, "TCP connect timeout for the sweep")
	fs.IntVarP(&f.requestTimeout, "request-timeout", "O", 60, "HTTP timeout for API requests (seconds)")
	fs.DurationVar(&f.sourceTimeout, "source-timeout", 3*time.Minute, "overall time limit per source per domain")
	fs.IntVarP(&f.delay, "delay", "t", 0, "seconds to wait between domains")
	fs.BoolVar(&f.force, "force", false, "allow ranges larger than /16 (and VirusTotal sweeps larger than /24)")
	fs.StringVarP(&f.configPath, "config", "c", "", "config file (default "+config.DefaultPath()+")")
	fs.BoolVar(&f.silent, "silent", false, "print only hostnames on stdout, no banner/progress")
	fs.BoolVarP(&f.verbose, "verbose", "v", false, "debug output")
	fs.BoolVar(&f.noColor, "no-color", false, "disable colours")
	fs.BoolVar(&f.showVersion, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: certcrunchy [-d domain | -D file | -i range] [options]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.showVersion {
		fmt.Fprintln(stdout, "certcrunchy", version)
		return 0
	}

	color := !f.noColor && os.Getenv("NO_COLOR") == "" && isTTY(stderr)
	log := logx.New(stderr, f.verbose, f.silent, color)

	cfg, err := config.Load(f.configPath)
	if err != nil {
		log.Error("config: %v", err)
		return 2
	}
	client := httpx.New(time.Duration(f.requestTimeout)*time.Second, version)
	all := source.All(source.Deps{HTTP: client, Cfg: cfg})

	if f.listSources {
		listSources(stdout, all, cfg)
		return 0
	}
	if !f.silent {
		if color {
			fmt.Fprintf(stderr, banner, version)
		} else {
			fmt.Fprintf(stderr, "CertCrunchy v%s\n\n", version)
		}
	}

	domains, err := collectDomains(f, stdin)
	if err != nil {
		log.Error("%v", err)
		return 2
	}
	if len(domains) == 0 && len(f.ranges) == 0 {
		log.Error("nothing to do: give -d/--domain, -D/--domains or -i/--iprange (or pipe domains on stdin)")
		fs.Usage()
		return 2
	}

	format := f.format
	if format == "" && f.output != "" {
		format = "csv"
	}
	if format != "" && !slices.Contains(output.Formats, format) {
		log.Error("unknown format %q (want %s)", format, strings.Join(output.Formats, ", "))
		return 2
	}

	selected, err := selectSources(all, f, log, len(domains) > 0)
	if err != nil {
		log.Error("%v", err)
		return 2
	}

	opts := pipeline.Options{
		Domains:            domains,
		Sources:            selected,
		ResolveConcurrency: f.threads,
		NoResolve:          f.noResolve,
		SNI:                f.sni,
		Pivot:              f.pivot,
		PivotMax:           f.pivotMax,
		OrgPivot:           f.orgPivot,
		OrgPivotMax:        f.orgPivotMax,
		SourceTimeout:      f.sourceTimeout,
		Delay:              time.Duration(f.delay) * time.Second,
		Log:                log,
	}
	if !f.noResolve || (len(f.ranges) > 0 && !f.noPTR) {
		opts.Resolver = resolve.New(f.resolvers, 3*time.Second)
	}

	if len(f.ranges) > 0 {
		rng, err := certscan.ParseRanges(f.ranges)
		if err != nil {
			log.Error("%v", err)
			return 2
		}
		if rng.Size.Cmp(big.NewInt(maxRange)) > 0 && !f.force {
			log.Error("range has %s addresses; the limit is %d (/16). Use --force to override", rng.Size, maxRange)
			return 2
		}
		ports, err := certscan.ParsePorts(f.ports)
		if err != nil {
			log.Error("%v", err)
			return 2
		}
		var lim *rate.Limiter
		if f.scanRate > 0 {
			lim = rate.NewLimiter(rate.Limit(f.scanRate), f.scanRate)
		}
		opts.Ranges, opts.Ports = rng, ports
		opts.Scanner = &certscan.Scanner{Timeout: f.connectTimeout, Concurrency: f.scanThreads, Limiter: lim}
		opts.PTR = !f.noPTR
		log.Info("sweeping %s addresses × %d port(s) for certificates", rng.Size, len(ports))

		if f.virustotal {
			vt := findSource[*source.VirusTotal](all)
			switch {
			case vt == nil || !vt.Info().HasKey:
				log.Error("-V/--virustotal needs a VirusTotal key (CERTCRUNCHY_VIRUSTOTAL_KEY or config file)")
				return 2
			case rng.Size.Cmp(big.NewInt(maxVTRange)) > 0 && !f.force:
				log.Error("VirusTotal sweep of %s addresses would take ~%s minutes on a free key; limit is %d without --force", rng.Size, new(big.Int).Div(rng.Size, big.NewInt(4)), maxVTRange)
				return 2
			}
			opts.VT = vt
		}
	}
	if f.orgPivot {
		opts.CTLogs = findSource[*source.CTLogs](all)
		if opts.Ranges == nil {
			log.Warn("--org-pivot only uses organisations from netblock certificates; add -i")
		}
	}
	if f.pivot && opts.Ranges == nil {
		log.Warn("--pivot only follows domains found in netblock certificates; add -i")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, runErr := pipeline.Run(ctx, opts)
	if runErr != nil {
		log.Warn("run interrupted (%v); writing partial results", runErr)
	}

	targets := append(append([]string{}, domains...), f.ranges...)
	outOpts := output.Options{Format: format, ResolvedOnly: f.resolvedOnly, Version: version, Targets: targets}

	if f.output != "" {
		if err := writeFile(f.output, res, outOpts); err != nil {
			log.Error("write %s: %v", f.output, err)
			return 1
		}
		log.Info("results saved to %s (%s)", f.output, outOpts.Format)
	}

	switch {
	case f.silent:
		err = output.Names(stdout, res, f.resolvedOnly)
	case f.output != "":
		err = output.Write(stdout, res, output.Options{Format: "text", ResolvedOnly: f.resolvedOnly, Color: color && isTTY(stdout)})
	default:
		outOpts.Color = color && isTTY(stdout)
		err = output.Write(stdout, res, outOpts)
	}
	if err != nil {
		log.Error("%v", err)
		return 1
	}
	if !f.silent {
		output.Summary(stderr, res, color)
	}
	if runErr != nil {
		return 130
	}
	return 0
}

func collectDomains(f flags, stdin *os.File) ([]string, error) {
	var raw []string
	raw = append(raw, f.domains...)
	readLines := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				raw = append(raw, line)
			}
		}
	}
	for _, path := range f.domainFile {
		if path == "-" {
			readLines(stdin)
			continue
		}
		fh, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("domains file: %w", err)
		}
		readLines(fh)
		fh.Close()
	}
	if len(raw) == 0 && len(f.ranges) == 0 && !isTTYFile(stdin) {
		readLines(stdin)
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range raw {
		for _, part := range strings.Split(r, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			d, ok := names.NormalizeDomain(part)
			if !ok {
				return nil, fmt.Errorf("invalid domain %q", part)
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out, nil
}

func selectSources(all []source.Source, f flags, log *logx.Logger, announce bool) ([]source.Source, error) {
	byName := map[string]source.Source{}
	for _, s := range all {
		byName[s.Info().Name] = s
	}
	check := func(list []string) error {
		for _, n := range list {
			if _, ok := byName[n]; !ok {
				return fmt.Errorf("unknown source %q (known: %s)", n, strings.Join(source.Names(all), ", "))
			}
		}
		return nil
	}
	if err := check(f.sources); err != nil {
		return nil, err
	}
	if err := check(f.exclude); err != nil {
		return nil, err
	}
	var out, skipped []string
	var selected []source.Source
	for _, s := range all {
		i := s.Info()
		want := i.Default || f.allSources
		if len(f.sources) > 0 {
			want = slices.Contains(f.sources, i.Name)
		}
		if !want || slices.Contains(f.exclude, i.Name) {
			continue
		}
		if !i.Usable() {
			skipped = append(skipped, i.Name)
			continue
		}
		selected = append(selected, s)
		out = append(out, i.Name)
	}
	if !announce {
		return selected, nil
	}
	log.Info("sources: %s", strings.Join(out, ", "))
	if len(skipped) > 0 {
		log.Debug("skipped (no API key): %s", strings.Join(skipped, ", "))
		if len(f.sources) > 0 {
			log.Warn("no API key for: %s", strings.Join(skipped, ", "))
		}
	}
	return selected, nil
}

func listSources(w io.Writer, all []source.Source, cfg *config.Config) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tDEFAULT\tKEY\tDESCRIPTION")
	for _, s := range all {
		i := s.Info()
		key := "-"
		switch {
		case i.KeyName == "":
		case i.HasKey:
			key = "set"
		case i.KeyRequired:
			key = "required (missing)"
		default:
			key = "optional"
		}
		def := "no"
		if i.Default {
			def = "yes"
		}
		if i.FallbackFor != "" {
			def = "fallback"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Name, i.Kind, def, key, i.Desc)
	}
	tw.Flush()
	p := cfg.Path
	if p == "" {
		p = config.DefaultPath() + " (not found)"
	}
	fmt.Fprintf(w, "\nKeys: env CERTCRUNCHY_<NAME>_KEY or %s\n", p)
}

func findSource[T source.Source](all []source.Source) T {
	var zero T
	for _, s := range all {
		if t, ok := s.(T); ok {
			return t
		}
	}
	return zero
}

func writeFile(path string, res *pipeline.Result, o output.Options) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := output.Write(fh, res, o); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && logx.IsTerminal(f)
}

func isTTYFile(f *os.File) bool { return f == nil || logx.IsTerminal(f) }
