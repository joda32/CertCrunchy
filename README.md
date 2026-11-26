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

<p align="center"><img src="docs/demo.gif" alt="CertCrunchy demo: passive CT lookup for example.com, then a certificate sweep of a small lab" width="860"></p>

## Wait, v2? 🎉

Yep. CertCrunchy started life years ago as a scrappy little Python script, and it served well. It also quietly aged: half the APIs it talked to moved house or shut down, crt.sh took naps at the worst moments, and the headline trick (scraping certs off whole IP ranges) had been politely ignoring every self-signed certificate it met. On internal networks that's... most of them. Oops.

So it got rebuilt from scratch in Go. It's faster, ships as one binary, asks several Certificate Transparency sources so one grumpy server can't ruin your day, and the cert sweep now actually eats everything it's served.

**Looking for the old Python version?** It's retired but not forgotten. Grab it from the [`v1-python` tag](https://github.com/joda32/CertCrunchy/tree/v1-python):

```sh
git clone --branch v1-python https://github.com/joda32/CertCrunchy.git certcrunchy-v1
```

It won't get updates, and several of its sources no longer answer, but it's there for nostalgia, old scripts and archaeology.

## What the?

CertCrunchy finds hostnames in two ways:

1. **Passive:** it asks a pile of Certificate Transparency (CT) search services and passive DNS APIs which names have ever been seen under a domain.
2. **The trick (netblock sweep):** it connects to every IP and port in a range *without SNI* and reads the default certificate each server hands over. Those certificates love to name hosts that appear nowhere else: internal names, appliances, management interfaces, forgotten vhosts.

Every name found is then checked with DNS (A/AAAA/CNAME), and names that only exist because of a wildcard record are flagged so they don't fool you.

## Install

```sh
go install github.com/joda32/certcrunchy/cmd/certcrunchy@latest   # Go 1.26+
```

Or download a binary from Releases, or `git clone … && make build`.

## How to use it?

```sh
certcrunchy -d example.com                      # passive sources + DNS validation
certcrunchy -D domains.txt -o out.json -f json  # many domains, JSON file
cat domains.txt | certcrunchy --silent          # bare hostnames on stdout, pipe-friendly
certcrunchy -i 203.0.113.0/24 -p web            # cert sweep on 443,8443,4443,9443,10443
certcrunchy -i 203.0.113.0/24 --sni --pivot     # + SNI vhost pass + follow new domains into CT
certcrunchy --list-sources                      # what's available and which keys are set
```

Chatter (progress and the per-source health table) goes to **stderr**; results go to **stdout** or the `-o` file. Ctrl-C still writes whatever was found so far.

### All the options

**What to look at**

| Flag | Meaning |
|---|---|
| `-d, --domain` | domain(s) to enumerate (repeatable or comma-separated) |
| `-D, --domains` | file with one domain per line (`#` comments allowed, `-` = stdin). Piping domains in with no flags works too |
| `-i, --iprange` | CIDR(s) or single IPs to sweep, IPv4 or IPv6, e.g. `10.0.0.0/24,2001:db8::/120` |
| `-p, --port` | TLS port(s) for the sweep: numbers and/or presets `web`, `mail`, `all` (default `443`) |
| `--force` | allow ranges bigger than a /16 (and VirusTotal sweeps bigger than a /24) |

**Passive sources**

| Flag | Meaning |
|---|---|
| `-s, --sources` | only use these sources, e.g. `-s crtsh-db,certspotter` |
| `-x, --exclude-sources` | skip these sources |
| `--all-sources` | also run opt-in sources (currently `rapiddns`) |
| `--list-sources` | show every source, whether it needs a key, and whether you've set one |
| `-c, --config` | config file with API keys (default `~/.config/certcrunchy/config.yaml`) |

**Netblock extras**

| Flag | Meaning |
|---|---|
| `--sni` | after resolving, re-probe hosts that live inside the range *with* SNI to reveal non-default vhost certificates |
| `--pivot` / `--pivot-max N` | feed new registrable domains found in netblock certs back into the passive sources (top 10 by default) |
| `--org-pivot` / `--org-pivot-max N` | search CT (ctlogs.dev) for other certificates issued to organisations seen in netblock certs (top 5 by default) |
| `-V, --virustotal` | also ask VirusTotal which hostnames resolved to each IP (free key: 4 IPs per minute, so think small) |
| `--no-ptr` | skip reverse DNS lookups for the range |

**DNS and output**

| Flag | Meaning |
|---|---|
| `--resolved-only` | only report names that resolve (the v1 behaviour; v2 keeps unresolved names because internal ones are often the good ones) |
| `--no-resolve` | skip DNS validation entirely |
| `-r, --resolvers` | DNS servers to use (`ip[:port]`, comma-separated); default is the system resolver |
| `-o, --output` | write results to a file |
| `-f, --format` | `text`, `csv`, `json` or `jsonl` (default `text`, or `csv` when `-o` is used) |
| `--silent` | hostnames only on stdout, no banner or progress |
| `-v, --verbose` / `--no-color` / `--version` | more chatter / no colours / print version |

**Speed and patience**

| Flag | Default | Meaning |
|---|---|---|
| `-T, --threads` | 50 | DNS and PTR concurrency |
| `--scan-threads` | 200 | concurrent TLS connections during the sweep |
| `--scan-rate` | 0 | max new TLS connections per second (0 = no limit) |
| `--connect-timeout` | 2s | TCP connect timeout for the sweep |
| `-O, --request-timeout` | 60 | HTTP timeout for API calls, in seconds |
| `--source-timeout` | 3m | total time budget per source, per domain |
| `-t, --delay` | 0 | seconds to wait between domains |

## Sources

| Name | Type | Key | Notes |
|---|---|---|---|
| `crtsh-db` | CT | – | crt.sh's public Postgres (`guest@crt.sh/certwatch`). Much faster and more reliable than its website |
| `crtsh` | CT | – | crt.sh JSON API; **only runs if `crtsh-db` fails** |
| `certspotter` | CT | optional | SSLMate Cert Spotter v1 issuances API |
| `ctlogs` | CT | optional | ctlogs.dev host index (current certs + 90 days); also powers `--org-pivot` |
| `censys` | CT | required | Censys Platform v3 (personal access token, optional `censys-org`) |
| `merklemap` | CT | required | Merklemap search (paid) |
| `virustotal` | pDNS | required | VirusTotal v3 subdomains; also the `-V` IP sweep |
| `hackertarget` | pDNS | optional | HackerTarget hostsearch (20/day keyless) |
| `otx` | pDNS | optional | AlienVault OTX passive DNS (a free key is strongly recommended) |
| `urlscan` | pDNS | optional | urlscan.io search |
| `rapiddns` | pDNS | – | HTML scrape; opt-in via `-s rapiddns` or `--all-sources` |

Free quotas are small, so expect a few `rate-limited` rows in the health table if you run it a lot. That table lists every source's outcome (`ok`, `empty`, `partial`, `rate-limited`, `timeout`, `error`), so a source having a bad day shows up as exactly that instead of looking like "no subdomains".

## API keys and configs

Every key is optional. Sources that need one are simply skipped without it. Keys are read from `~/.config/certcrunchy/config.yaml` (copy [`config.example.yaml`](config.example.yaml)) or from environment variables named `CERTCRUNCHY_<NAME>_KEY`, for example `CERTCRUNCHY_VIRUSTOTAL_KEY` or `CERTCRUNCHY_CENSYS_ORG_KEY`. The environment wins over the file.

## How the netblock sweep works

For each IP and port, CertCrunchy does a TLS handshake without SNI and grabs the leaf certificate **before any validation happens**. So self-signed, private-CA, expired and otherwise sketchy certificates are all collected, and those are exactly what internal ranges are full of. The certificate is kept even if the server hangs up right after (say, because it wants a client certificate), and legacy ciphers and TLS 1.0 are on offer for elderly appliances.

From each certificate it pulls:

- **Hostnames:** the CN, every DNS SAN, the domain part of email SANs (`noc@mail.corp.internal` → `mail.corp.internal`) and the host part of URI SANs (`https://grafana.corp.internal/` → `grafana.corp.internal`). Each one has to pass a hostname sanity check, so junk like `Fortinet` or `192.168.1.1` doesn't get in.
- **IP SANs** (and an IP-address CN): recorded in the JSON output. Any that sit *outside* the range you're scanning are called out while it runs, because a device listing its other addresses is a hint about where to look next.
- **Metadata:** organisation, issuer, self-signed/expired flags and the SHA-256 fingerprint (all in JSON output).

Hosts that resolve back into the scanned range are marked `in_range`. With `--sni`, those get a second knock with their name in SNI, to coax out certificates for other virtual hosts.

## Moving over from v1

| v1 | v2 |
|---|---|
| `api_keys.py` | config file or env vars (see above) |
| CertDB, PassiveTotal, CertSpotter v0, VirusTotal v2, Censys v1/v2 | removed (gone or deprecated upstream) and replaced by the sources above |
| only resolving names reported | everything reported; add `--resolved-only` for the old behaviour |
| CSV `host,ip,ip,…` | CSV with a header: `host,resolved,wildcard,in_range,ips,cnames,sources` |
| `-t` delay default 3s | default 0 (each source has its own rate limiter now) |
| `-O` default 10s | default 60s (crt.sh can be slow) |

## Development

```sh
make test      # unit + fixture tests (offline)
make race      # with the race detector
make live      # real queries to the passive sources (LIVE_DOMAIN=…, LIVE_SOURCES=…)
make lint      # go vet + staticcheck
```

The demo GIF was recorded against a tiny localhost lab. Its recording lives in [`docs/demo.cast`](docs/demo.cast), so the GIF can be re-themed without re-recording.

Be nice: only scan networks you're allowed to test.
