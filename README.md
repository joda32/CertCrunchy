```
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
```

Just a silly recon tool that uses SSL/TLS certificate data to find hostnames.

CertCrunchy finds subdomains in two ways:

1. **Passive:** it asks several Certificate Transparency (CT) search services and passive DNS APIs which names have been seen under a domain.
2. **Netblock sweep:** it connects to every IP in a range *without SNI* and reads the default certificate each server presents. Those certificates often name hosts that appear nowhere else: internal names, appliances, forgotten vhosts.

Every candidate name is then checked with DNS (A/AAAA/CNAME), and names that match a wildcard record are flagged.

v2 is a rewrite in Go: a single static binary with redundant CT sources and a fixed and extended netblock sweep. The original Python version is preserved at the [`v1-python`](../../tree/v1-python) tag.

## Install

```sh
go install github.com/joda32/certcrunchy/cmd/certcrunchy@latest   # Go 1.26+
```

Or download a binary from Releases, or `git clone … && make build`.

## Usage

```sh
certcrunchy -d example.com                      # passive sources + DNS validation
certcrunchy -D domains.txt -o out.json -f json  # many domains, JSON file
cat domains.txt | certcrunchy --silent          # bare hostnames on stdout, pipe-friendly
certcrunchy -i 203.0.113.0/24 -p web            # certificate sweep on 443,8443,4443,9443,10443
certcrunchy -i 203.0.113.0/24 --sni --pivot     # + SNI vhost pass + follow new domains into CT
certcrunchy --list-sources                      # what's available and which keys are set
```

Progress and the per-source health table go to **stderr**; results go to **stdout** (or `-o`).

| Flag | Meaning |
|---|---|
| `-d, --domain` | domain(s) to enumerate (repeatable / comma-separated) |
| `-D, --domains` | file with one domain per line (`#` comments; `-` = stdin) |
| `-i, --iprange` | CIDR(s) or IPs to sweep, IPv4 and IPv6 (max /16 without `--force`) |
| `-p, --port` | TLS port(s) for the sweep: numbers or presets `web`, `mail`, `all` (default 443) |
| `-o, --output` / `-f, --format` | output file / `text`, `csv`, `json`, `jsonl` (default text; csv when `-o` is used) |
| `-s, --sources` / `-x, --exclude-sources` | choose passive sources; `--all-sources` adds opt-in ones |
| `--resolved-only` | only report names that resolve (the v1 behaviour; v2 keeps unresolved names by default) |
| `--no-resolve`, `-r, --resolvers` | skip DNS validation / use specific resolvers |
| `--sni` | re-probe in-range hosts with SNI to reveal non-default vhost certificates |
| `--pivot` | feed new registrable domains seen in netblock certs back into the passive sources |
| `--org-pivot` | search CT (ctlogs.dev) for other certificates of organisations seen in netblock certs |
| `-V, --virustotal` | also ask VirusTotal which hostnames resolved to each IP (free key: 4 IPs/min, max /24 without `--force`) |
| `--no-ptr` | skip reverse DNS for the range |
| `-T, --threads` / `--scan-threads` / `--scan-rate` | DNS concurrency / TLS connection concurrency / connections per second |
| `--connect-timeout`, `-O, --request-timeout`, `--source-timeout` | sweep connect timeout / HTTP timeout / per-source budget |
| `--silent`, `-v`, `--no-color` | names only / debug output / plain output |

## Sources

| Name | Type | Key | Notes |
|---|---|---|---|
| `crtsh-db` | CT | – | crt.sh's public Postgres (`guest@crt.sh/certwatch`). Much faster and more reliable than the web API |
| `crtsh` | CT | – | crt.sh JSON API; **only runs if `crtsh-db` fails** |
| `certspotter` | CT | optional | SSLMate Cert Spotter v1 issuances API |
| `ctlogs` | CT | optional | ctlogs.dev host index (current certs + 90 days); also powers `--org-pivot` |
| `censys` | CT | required | Censys Platform v3 (personal access token, optional `censys-org`) |
| `merklemap` | CT | required | Merklemap search (paid) |
| `virustotal` | pDNS | required | VirusTotal v3 subdomains; also `-V` IP resolutions |
| `hackertarget` | pDNS | optional | HackerTarget hostsearch (20/day keyless) |
| `otx` | pDNS | optional | AlienVault OTX passive DNS (a free key is strongly recommended) |
| `urlscan` | pDNS | optional | urlscan.io search |
| `rapiddns` | pDNS | – | HTML scrape; opt-in via `-s rapiddns` or `--all-sources` |

Free quotas are small, so expect `rate-limited` rows in the health table when running a lot. The table lists every source's outcome (`ok`, `empty`, `partial`, `rate-limited`, `timeout`, `error`), so an outage is visible instead of looking like "no subdomains".

## API keys

Keys are read from `~/.config/certcrunchy/config.yaml` (see [`config.example.yaml`](config.example.yaml)) or from environment variables named `CERTCRUNCHY_<NAME>_KEY` (for example `CERTCRUNCHY_VIRUSTOTAL_KEY`, `CERTCRUNCHY_CENSYS_ORG_KEY`). The environment wins over the file.

## How the netblock sweep works

For each IP and port, CertCrunchy completes a TLS handshake without SNI and captures the leaf certificate **before any validation**. That means self-signed, private-CA, expired and otherwise broken certificates are all harvested, which is what you meet on internal ranges. The certificate is kept even if the server aborts the handshake afterwards (for example, by requiring a client certificate). Legacy cipher suites and TLS 1.0 are offered for old appliances.

It records the CN and SAN names, plus the organisation, issuer, self-signed and expired flags, and the SHA-256 fingerprint (visible in JSON output). Hosts that resolve back into the scanned range are marked `in_range`. With `--sni`, those hosts are probed again with SNI to uncover certificates of other virtual hosts.

## Migrating from v1

| v1 | v2 |
|---|---|
| `api_keys.py` | config file or env vars (see above) |
| CertDB, PassiveTotal, CertSpotter v0, VirusTotal v2, Censys v1/v2 | removed (all dead or deprecated) and replaced by the sources above |
| only resolving names reported | all names reported; add `--resolved-only` for the old behaviour |
| CSV `host,ip,ip,…` | CSV with a header: `host,resolved,wildcard,in_range,ips,cnames,sources` |
| `-t` delay default 3s | default 0 (each source has its own rate limiter) |
| `-O` default 10s | default 60s (crt.sh can be slow) |

## Development

```sh
make test      # unit + fixture tests (offline)
make race      # with the race detector
make live      # real queries to the passive sources (LIVE_DOMAIN=…, LIVE_SOURCES=…)
make lint      # go vet + staticcheck
```

Only scan networks you are authorised to test.
