import httpx, concurrent.futures

def bust(base, wordlist, threads=20, timeout=5):
    words = [w.strip() for w in open(wordlist) if w.strip()]
    hits = []
    def probe(w):
        url = f"{base.rstrip('/')}/{w}"
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                hits.append({"url": url, "status": r.status_code, "len": len(r.content)})
        except Exception:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(probe, words))
    return hits
