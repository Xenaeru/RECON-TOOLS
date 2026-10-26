import httpx, concurrent.futures, socket

CRT = "https://crt.sh/?q=%25.{domain}&output=json"

def from_crtsh(domain, timeout=20):
    out = set()
    try:
        r = httpx.get(CRT.format(domain=domain), timeout=timeout,
                      headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            for row in r.json():
                for name in row.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and "@" not in name:
                        out.add(name)
    except Exception:
        pass
    return out

def from_wordlist(domain, wordlist, threads=20, timeout=3):
    words = [w.strip() for w in open(wordlist) if w.strip()]
    out = []
    def probe(w):
        host = f"{w}.{domain}"
        try:
            socket.gethostbyname(host)
            out.append(host)
        except Exception:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(probe, words))
    return set(out)

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def enumerate(domain, wordlist=None, threads=20, timeout=20, use_crt=True):
    subs = set()
    if use_crt:
        subs |= from_crtsh(domain, timeout)
    if wordlist:
        subs |= from_wordlist(domain, wordlist, threads, 3)
    alive = {}
    for s in sorted(subs):
        ip = resolve(s)
        if ip:
            alive[s] = ip
    return alive
