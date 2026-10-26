import yaml, httpx
from urllib.parse import urlparse, parse_qs
from models import Finding, Report
from scanners import portscan, http_enum, dirbust, subdomain
from detectors import sqli, xss, idor, headers
from exploiter import run_all
from reporter import render
from riskmap import annotate

def load(cfg="config.yaml"):
    return yaml.safe_load(open(cfg))

def _probe_host(base_url, timeout, cfg):
    """Light scan: engine, headers, param detectors. Returns list[Finding]."""
    out = []
    try:
        enum = http_enum.enum(
            base_url, timeout,
            use_playwright=cfg.get("use_playwright", True),
            playwright_timeout_ms=cfg.get("playwright_timeout_ms", 20000),
            cf_bypass=cfg.get("cf_bypass", True),
            cf_impersonate=cfg.get("cf_impersonate", "chrome124"),
        )
    except Exception as e:
        out.append(Finding(kind="engine", url=base_url,
                           evidence=f"enum error: {e}", severity="info"))
        return out
    
    out.append(Finding(kind="engine", url=base_url,
        evidence=f"{enum['engine']} / cf={enum['cf']} / status={enum['status']}",
        severity="info"))
    
    if enum["status"] == 0:
        return out

    for h in headers.detect(base_url, timeout):
        out.append(Finding(kind="header", url=base_url, evidence=h["evidence"]))
    
    for link in enum["links"][:50]:
        qs = parse_qs(urlparse(link).query)
        for p in qs:
            for hit in sqli.detect(link, p, timeout):
                out.append(Finding(kind="sqli", url=link, param=p,
                    payload=hit["payload"], evidence=hit["evidence"]))
            for hit in xss.detect(link, p, timeout):
                out.append(Finding(kind="xss", url=link, param=p,
                    payload=hit["payload"], evidence=hit["evidence"]))
            for hit in idor.detect(link, p, timeout):
                out.append(Finding(kind="idor", url=link, param=p,
                    payload=str(hit["value"]), evidence=hit["evidence"]))
    return out

def run(cfg_path="config.yaml"):
    cfg = load(cfg_path)
    target = cfg["target"]
    host = httpx.URL(target).host
    rep = Report(target=target)

    rep.open_ports = portscan.scan(host, cfg.get("port_range", "1-1000"))

    enum = http_enum.enum(
        target, cfg["timeout"],
        use_playwright=cfg.get("use_playwright", True),
        playwright_timeout_ms=cfg.get("playwright_timeout_ms", 20000),
        cf_bypass=cfg.get("cf_bypass", True),
        cf_impersonate=cfg.get("cf_impersonate", "chrome124"),
    )
    rep.endpoints = enum["links"]

    rep.findings.append(Finding(kind="engine", url=target,
        evidence=f"{enum['engine']} / cf={enum['cf']} / status={enum['status']}",
        severity="info"))

    # Abort if host is down
    if enum["status"] == 0:
        for f in rep.findings:
            annotate(f)
        return render(rep, cfg["report_out"]), rep

    rep.findings += [
        Finding(kind="dirbust", url=h["url"],
                evidence=f"status {h['status']}", severity="low")
        for h in dirbust.bust(target, cfg["wordlist"], cfg["threads"], cfg["timeout"])
    ]

    for h in headers.detect(target, cfg["timeout"]):
        rep.findings.append(Finding(kind="header", url=target,
                                    evidence=h["evidence"], severity="low"))

    # (Juice Shop injection removed here)

    for link in enum["links"][:50]:
        qs = parse_qs(urlparse(link).query)
        for p in qs:
            for hit in sqli.detect(link, p, cfg["timeout"]):
                rep.findings.append(Finding(kind="sqli", url=link, param=p,
                    payload=hit["payload"], evidence=hit["evidence"]))
            for hit in xss.detect(link, p, cfg["timeout"]):
                rep.findings.append(Finding(kind="xss", url=link, param=p,
                    payload=hit["payload"], evidence=hit["evidence"]))
            for hit in idor.detect(link, p, cfg["timeout"]):
                rep.findings.append(Finding(kind="idor", url=link, param=p,
                    payload=str(hit["value"]), evidence=hit["evidence"]))

    if cfg.get("enum_subdomains", True):
        sub_wl = cfg.get("subdomain_wordlist")
        subs = subdomain.enumerate(
            host, wordlist=sub_wl,
            threads=cfg.get("subdomain_threads", 20),
            timeout=cfg["timeout"],
            use_crt=True,
        )
        rep.subdomains = subs
        if cfg.get("subdomain_scan", True):
            for sub, ip in subs.items():
                if sub == host:
                    continue
                base = f"https://{sub}"
                try:
                    httpx.get(base, timeout=cfg["timeout"], verify=False)
                except Exception:
                    base = f"http://{sub}"
                rep.findings += _probe_host(base, cfg["timeout"], cfg)

    for kind, res in run_all(target, rep.findings, cfg["timeout"]):
        for f in rep.findings:
            if f.kind == kind and not f.exploited:
                f.exploited = bool(res.get("hit") or res.get("reflected") or res)
                f.detail = res

    for f in rep.findings:
        annotate(f)

    out = render(rep, cfg["report_out"])
    return out, rep
