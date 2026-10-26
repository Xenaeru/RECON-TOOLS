import asyncio
from playwright.async_api import async_playwright

async def fetch_rendered(url, timeout_ms=20000):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True,
            args=["--disable-blink-features=AutomationControlled"])
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            locale="en-US",
        )
        page = await ctx.new_page()
        await page.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        except Exception:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            await page.wait_for_timeout(2000)
        html = await page.content()
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)")
        forms = await page.eval_on_selector_all(
            "form",
            "els => els.map(f => ({action:f.action, method:f.method,"
            " inputs:[...f.elements].map(e=>e.name).filter(Boolean)}))")
        status = resp.status if resp else 0
        server = (resp.headers.get("server", "") if resp else "")
        await browser.close()
        return {"html": html, "links": sorted(set(links)),
                "forms": forms, "status": status, "server": server}

def fetch(url, timeout_ms=20000):
    return asyncio.run(fetch_rendered(url, timeout_ms))
