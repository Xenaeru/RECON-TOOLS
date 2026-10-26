import httpx
from bs4 import BeautifulSoup
from . import browser, cf
from urllib.parse import urlparse

def enum(base, timeout=10, use_playwright=True,
         playwright_timeout_ms=20000, cf_bypass=True,
         cf_impersonate="chrome124"):
    
    base_host = urlparse(base).netloc

    def filter_links(raw_links):
        valid = []
        for link in raw_links:
            if urlparse(link).netloc == base_host or not urlparse(link).netloc:
                valid.append(link)
        return sorted(set(valid))

    if cf_bypass:
        cr = cf.fetch(base, cf_impersonate, timeout)
        if cf.is_challenge(cr["text"], cr["headers"]):
            if use_playwright:
                pr = browser.fetch(base, playwright_timeout_ms)
                return {"links": filter_links(pr["links"]), "forms": pr["forms"],
                        "status": pr["status"], "server": pr["server"],
                        "engine": "playwright", "cf": "challenged"}
        else:
            soup = BeautifulSoup(cr["text"], "html.parser")
            links = {str(httpx.URL(base).join(a["href"]))
                     for a in soup.find_all("a", href=True)}
            forms = [{"action": f.get("action", ""),
                      "method": f.get("method", "get").lower(),
                      "inputs": [i.get("name") for i in
                                 f.find_all(["input", "textarea"])]}
                     for f in soup.find_all("form")]
            return {"links": filter_links(links), "forms": forms,
                    "status": cr["status"],
                    "server": cr["headers"].get("server", ""),
                    "engine": cr["engine"], "cf": "clear"}

    if use_playwright:
        pr = browser.fetch(base, playwright_timeout_ms)
        return {"links": filter_links(pr["links"]), "forms": pr["forms"],
                "status": pr["status"], "server": pr["server"],
                "engine": "playwright", "cf": "unknown"}

    r = httpx.get(base, timeout=timeout, follow_redirects=False)
    soup = BeautifulSoup(r.text, "html.parser")
    links = {str(httpx.URL(base).join(a["href"]))
             for a in soup.find_all("a", href=True)}
    forms = [{"action": f.get("action", ""),
              "method": f.get("method", "get").lower(),
              "inputs": [i.get("name") for i in
                         f.find_all(["input", "textarea"])]}
             for f in soup.find_all("form")]
    return {"links": filter_links(links), "forms": forms, "status": r.status_code,
            "server": r.headers.get("server", ""), "engine": "httpx",
            "cf": "unknown"}
