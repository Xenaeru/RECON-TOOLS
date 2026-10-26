from curl_cffi import requests as cffi
import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

def fetch(url, impersonate="chrome124", timeout=15):
    try:
        r = cffi.get(url, impersonate=impersonate, timeout=timeout,
                     allow_redirects=True)
        return {"status": r.status_code, "text": r.text,
                "headers": dict(r.headers), "engine": "curl_cffi"}
    except Exception:
        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": UA})
        return {"status": r.status_code, "text": r.text,
                "headers": dict(r.headers), "engine": "httpx-fallback"}

def is_challenge(resp_text, resp_headers):
    h = {k.lower(): v for k, v in resp_headers.items()}
    if h.get("cf-mitigated", "").lower() == "challenge":
        return True
    markers = ["Just a moment", "cf-browser-verification",
               "Checking your browser before accessing",
               "/cdn-cgi/challenge-platform/"]
    return any(m in resp_text for m in markers)
