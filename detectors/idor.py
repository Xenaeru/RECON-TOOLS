import httpx

def detect(url, param, timeout=10, samples=(1, 2, 3, 100)):
    if "cloudflare.com" in url or "errorcode_502" in url:
        return []
    
    # Abaikan parameter pencarian (search, q, query, dll) karena ini bukan IDOR
    skip_params = ["search", "q", "query", "s", "keyword", "page"]
    if param.lower() in skip_params:
        return []

    out = []
    base_len = 0
    
    # Dapatkan ukuran respons normal
    try:
        base_r = httpx.get(url, params={param: "test"}, timeout=timeout)
        if base_r.status_code != 200:
            return []
        base_len = len(base_r.content)
    except Exception:
        return []

    for s in samples:
        try:
            r = httpx.get(url, params={param: s}, timeout=timeout)
        except Exception:
            continue
            
        if r.status_code == 200:
            current_len = len(r.content)
            # Hanya anggap IDOR jika ukuran responsnya berubah drastis (lebih dari 50%)
            # Jika IDOR asli, mengubah ID user akan menampilkan halaman dengan ukuran yang sangat berbeda
            len_diff = abs(current_len - base_len)
            if len_diff > (base_len * 0.5) and current_len > 100:
                out.append({"param": param, "value": s,
                            "evidence": f"status 200, massive len diff ({base_len}->{current_len})"})
    return out
