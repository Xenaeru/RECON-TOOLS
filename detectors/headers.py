import httpx

CHECKS = {
    "content-security-policy": "missing CSP",
    "x-frame-options": "clickjacking",
    "strict-transport-security": "no HSTS",
    "x-content-type-options": "MIME sniffing",
}

def detect(url, timeout=10):
    try:
        r = httpx.get(url, timeout=timeout)
    except Exception:
        return []
    present = {k.lower() for k in r.headers}
    return [{"header": h, "evidence": m} for h, m in CHECKS.items() if h not in present]
