# RECON TOOLS

Web reconnaissance pipeline. Port scan, HTTP enumeration, directory brute force, header checks, SQLi/XSS/IDOR detection, non-destructive PoC exploitation, subdomain discovery, HTML report with severity, CVSS, risk description, and per-class exploit surface.

**Authorized testing only.** Runs port scans, injection payloads, and browser sessions against whatever host is in `config.yaml`. Point it at hosts you own or have written permission to test.

## Features

- **Port scan** — nmap `-sT -T4` over configurable range (`python-nmap`).
- **HTTP enum** — curl_cffi TLS-fingerprint fetch, Cloudflare-challenge detection, Playwright headless Chromium fallback for JS-rendered pages. Extracts links and forms.
- **Directory brute** — wordlist probe at configurable thread count; flags 200/301/302/401/403.
- **Header audit** — CSP, X-Frame-Options, HSTS, X-Content-Type-Options.
- **Detectors** — SQLi (error signature + length delta), XSS (marker reflection), IDOR (sequential ID enumeration).
- **PoC exploitation** — UNION probe, `onerror` reflection check, ID enumeration. Non-destructive; sets `exploited` and stores response detail per finding.
- **Subdomain discovery** — crt.sh passive CT lookup + optional DNS wordlist brute. Per-subdomain light scan (enum + headers + param detectors).
- **Report** — static HTML with severity color (critical/high/medium/low/info), CVSS score, one-line risk rationale, collapsible exploit-surface list per finding. JSON also printed to stdout.

## Requirements

- Linux (tested on Kali), Python 3.13+ recommended (3.14.8 works; 3.12.4 also fine)
- `nmap` binary: `sudo apt install nmap`
- System libs for Playwright: `sudo python -m playwright install-deps chromium`

## Install

```bash
git clone <repo> recon_ai && cd recon_ai
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

Wordlists (drop in repo root):

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O common.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains.txt
```

## Usage

```bash
source .venv/bin/activate
python main.py config.yaml
```

Output:
- Report file at `report_out` (default `reports/scan_001.html`)
- JSON findings + ports to stdout

Open the report:
```bash
xdg-open reports/scan_001.html
```

Multiple targets:
```bash
mkdir -p configs
cp config.yaml configs/target-a.yaml
sed -i 's|^target:.*|target: "https://target-a.example"|' configs/target-a.yaml
sed -i 's|^report_out:.*|report_out: "reports/target-a.html"|' configs/target-a.yaml
python main.py configs/target-a.yaml
```

## Configuration

`config.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `target` | `http://127.0.0.1:8080` | Base URL. Scheme required. |
| `threads` | `20` | dirbust concurrency |
| `timeout` | `10` | per-request seconds |
| `port_range` | `"1-1000"` | nmap range |
| `wordlist` | `"common.txt"` | dirbust wordlist |
| `report_out` | `"reports/scan_001.html"` | report path |
| `use_playwright` | `true` | browser fallback for JS/CF |
| `playwright_timeout_ms` | `20000` | browser page timeout |
| `cf_bypass` | `true` | TLS-fingerprint layer |
| `cf_impersonate` | `"chrome124"` | curl_cffi profile |
| `enum_subdomains` | `true` | run subdomain pass |
| `subdomain_wordlist` | `"subdomains.txt"` | DNS brute list; `null` to skip |
| `subdomain_threads` | `20` | DNS brute concurrency |
| `subdomain_scan` | `true` | light scan per live sub |

## Architecture

```
main.py              entry — loads config, calls orchestrator.run()
orchestrator.py      wires scanner → detector → exploiter → reporter
models.py            Finding, Report dataclasses
riskmap.py           severity / cvss / risk text per finding kind
exploitmap.py        exploit-technique surface per finding kind
exploiter.py         non-destructive PoC confirmations

scanners/
  portscan.py        nmap wrapper
  http_enum.py       CF-aware fetch + link/form extraction
  dirbust.py         threaded wordlist probe
  browser.py         Playwright headless fetch
  cf.py              curl_cffi TLS-fingerprint fetch
  subdomain.py       crt.sh + DNS brute

detectors/
  sqli.py            error + length-delta heuristic
  xss.py             marker reflection
  idor.py            sequential ID probe
  headers.py         security-header audit

reporter.py          Jinja2 → static HTML
```

## Detection limits (read before trusting a clean report)

- SQLi/XSS/IDOR fire only on links with query parameters discovered on the base page. A login-gated app, POST-only form, or JS-only route is invisible unless Playwright renders it.
- Detectors are heuristic: SQLi uses error signatures and length deltas, XSS uses marker reflection. Both produce false positives and false negatives. Confirm manually before reporting.
- `dirbust` swallows per-probe exceptions; a run returning zero hits may mean the host soft-404s or rate-limited, not that no paths exist.
- Subdomain DNS brute detects resolvers only. Wildcard DNS inflates results.
- `exploitmap.py` lists exploit techniques per class as descriptive text. The executable layer is limited to the three PoC confirmations in `exploiter.py`. No blind SQLi extraction, no file-write, no stored-XSS payload delivery, no auth bypass.
- Cloudflare: curl_cffi defeats TLS-fingerprint and managed-challenge 403s. Interactive Turnstile/CAPTCHA is not solved.

## Legal

Scanning hosts without authorization is illegal in most jurisdictions (CFAA US, Computer Misuse Act UK, UU ITE ID, and equivalents). You are responsible for the `target` value and for every subdomain the tool enumerates. Use only on:

- hosts you own,
- lab environments (DVWA, Juice Shop, your own Flask app), or
- targets covered by written permission.

No warranty. No liability for misuse.

## License

MIT (or your choice — replace this section).
```

Add alongside in the repo root:

**.gitignore**
```
.venv/
__pycache__/
*.pyc
reports/
configs/
common.txt
subdomains.txt
```

Keep `config.yaml` tracked as a template; move real targets to `configs/` (ignored).
