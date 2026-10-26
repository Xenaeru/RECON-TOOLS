import httpx, uuid

def detect(url, param, timeout=10):
    if "cloudflare.com" in url or "errorcode_502" in url:
        return []

    marker = "xss" + uuid.uuid4().hex[:8]
    payload = f"<script>alert('{marker}')</script>"
    try:
        r = httpx.get(url, params={param: payload}, timeout=timeout)
    except Exception:
        return []
    if r.status_code == 200 and payload in r.text:
        return [{"param": param, "payload": payload, "evidence": "unencoded reflection"}]
    return []
