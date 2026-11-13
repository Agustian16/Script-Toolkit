#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf_ghost.py — Advanced Cloudflare / modern-WAF bypass client.

Escalation ladder:
    L0  curl_cffi impersonated TLS(JА3/JА4) + HTTP/2 request
    L1  identity rotation (new TLS fingerprint + new sticky egress IP)
    L2  headless Chromium + stealth patches -> solve JSVM -> harvest cf_clearance
    L3  third-party Turnstile solver (CapSolver / 2Captcha)

Deps:  pip install curl_cffi playwright && playwright install chromium
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from curl_cffi import requests as creq

try:
    from curl_cffi.const import CurlHttpVersion
except Exception:  # pragma: no cover
    CurlHttpVersion = None

log = logging.getLogger("cfghost")

STATE_DIR = Path.home() / ".cache" / "cf_ghost"
STATE_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# 1.  IDENTITIES  — TLS/HTTP2 fingerprint + coherent header set
# --------------------------------------------------------------------------- #
# NOTE: we let curl_cffi own the *default* headers (it emits them in the exact
# browser order for the profile). We only inject the volatile ones
# (sec-fetch-*, referer). Do NOT hand-write a full UA/accept block unless you
# also hand-write the order — you will desync from the TLS fingerprint.

@dataclass(frozen=True)
class Identity:
    name: str
    impersonate: str            # curl_cffi profile, or use ja3=/akamai= directly
    ua_hint: str
    is_chrome_like: bool = True
    http_version: str = "v2"    # "v2" | "v3"
    ja3: str | None = None      # optional custom JA3 string
    akamai: str | None = None   # optional custom h2 fingerprint


CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"

IDENTITIES: tuple[Identity, ...] = (
    Identity("chrome131_win",  "chrome131",  CHROME),
    Identity("chrome124_win",  "chrome124",  CHROME),
    Identity("chrome120_mac",  "chrome120",  CHROME),
    Identity("firefox133_win", "firefox133", FIREFOX, is_chrome_like=False),
    Identity("safari18_mac",   "safari18_0", SAFARI,  is_chrome_like=False),
)

ACCEPT_DOC = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7")
ACCEPT_XHR = "application/json, text/plain, */*"


def fetch_metadata(kind: str, url: str, referer: str | None = None) -> dict[str, str]:
    """
    sec-fetch-* must be COHERENT with the actual navigation. A 'navigate'
    request carrying sec-fetch-mode: cors is a cheap bot tell.
    """
    host = urlparse(url).netloc
    if kind == "navigate":
        h = {
            "accept": ACCEPT_DOC,
            "sec-fetch-site": "none" if not referer else "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "upgrade-insecure-requests": "1",
        }
    elif kind == "xhr":
        ref_host = urlparse(referer).netloc if referer else host
        h = {
            "accept": ACCEPT_XHR,
            "sec-fetch-site": "same-origin" if ref_host == host else "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
    else:  # subresource
        h = {
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "image",
        }
    if referer:
        h["referer"] = referer
    return h


# --------------------------------------------------------------------------- #
# 2.  VERDICT CLASSIFIER
# --------------------------------------------------------------------------- #
class Verdict(IntEnum):
    OK = 0
    JS_CHALLENGE = 1
    TURNSTILE = 2
    HARD_BLOCK = 3
    RATE_LIMIT = 4
    NETWORK = 5


BODY_MARKERS = {
    "js": ("just a moment", "cf-chl", "__cf_chl_", "challenge-platform",
           "cf_chl_opt", "_cf_chl_", "enable javascript and cookies"),
    "ts": ("cf-turnstile", "turnstile.render", "data-sitekey"),
    "block": ("attention required", "error 1020", "error 1006", "error 1010",
              "you have been blocked", "access denied"),
}

SITEKEY_RE = re.compile(r'data-sitekey=["\']([0-9A-Za-z_-]{20,})["\']')
SITEKEY_JS_RE = re.compile(r'sitekey\s*[:=]\s*["\']([0-9A-Za-z_-]{20,})["\']')


def classify(resp) -> tuple[Verdict, dict[str, Any]]:
    h = {k.lower(): v for k, v in resp.headers.items()}
    body = (resp.text or "")[:200_000].lower()
    meta: dict[str, Any] = {"status": resp.status_code, "cf_ray": h.get("cf-ray"),
                            "server": h.get("server")}

    if h.get("cf-mitigated") == "challenge":
        return Verdict.JS_CHALLENGE, meta
    if resp.status_code == 429:
        return Verdict.RATE_LIMIT, meta
    if any(m in body for m in BODY_MARKERS["ts"]):
        m = SITEKEY_RE.search(resp.text or "") or SITEKEY_JS_RE.search(resp.text or "")
        meta["sitekey"] = m.group(1) if m else None
        return Verdict.TURNSTILE, meta
    if any(m in body for m in BODY_MARKERS["js"]):
        return Verdict.JS_CHALLENGE, meta
    if resp.status_code in (403, 503) or any(m in body for m in BODY_MARKERS["block"]):
        return Verdict.HARD_BLOCK, meta
    if resp.status_code >= 400:
        return Verdict.HARD_BLOCK, meta
    return Verdict.OK, meta


# --------------------------------------------------------------------------- #
# 3.  SUPPORT: rate limit, proxy pool, cookie vault
# --------------------------------------------------------------------------- #
class TokenBucket:
    def __init__(self, rate: float, burst: int = 5):
        self.rate, self.burst = rate, burst
        self.tokens, self.last = float(burst), time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> float:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                self.tokens = 0.0
                self.last = now + wait
                return wait
            self.tokens -= 1
            return 0.0


class ProxyPool:
    """Sticky egress: one identity -> one IP, so cf_clearance stays valid."""

    def __init__(self, proxies: Sequence[str] = ()):
        self.proxies = list(proxies)

    def __bool__(self) -> bool:
        return bool(self.proxies)

    def for_identity(self, identity: str, attempt: int = 0) -> str | None:
        if not self.proxies:
            return None
        idx = (hash(identity) + attempt) % len(self.proxies)
        return self.proxies[idx]

    @staticmethod
    def as_curl(proxy: str | None) -> dict[str, str] | None:
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}


class CookieVault:
    """
    cf_clearance is bound to (egress IP, User-Agent, TLS fingerprint).
    Key the vault on identity+proxy, never on hostname alone.
    """

    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, list[dict]] = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text())
            except Exception:
                self._data = {}

    @staticmethod
    def key(identity: str, proxy: str | None, host: str) -> str:
        return f"{identity}|{proxy or 'direct'}|{host}"

    def load_into(self, session, identity: str, proxy: str | None, host: str) -> int:
        cookies = self._data.get(self.key(identity, proxy, host), [])
        for c in cookies:
            try:
                session.cookies.set(c["name"], c["value"],
                                    domain=c.get("domain", ""), path=c.get("path", "/"))
            except Exception:
                pass
        return len(cookies)

    def save_from(self, session, identity: str, proxy: str | None, host: str) -> None:
        out = []
        for c in session.cookies.jar:
            out.append({"name": c.name, "value": c.value, "domain": c.domain,
                        "path": c.path or "/"})
        if out:
            self._data[self.key(identity, proxy, host)] = out
            self.path.write_text(json.dumps(self._data, indent=1))


# --------------------------------------------------------------------------- #
# 4.  L3 — Turnstile solver API
# --------------------------------------------------------------------------- #
class TurnstileSolver:
    def __init__(self, api_key: str, provider: str = "capsolver"):
        self.api_key, self.provider = api_key, provider

    def solve(self, url: str, sitekey: str, proxy: str | None = None,
              timeout: int = 120) -> str | None:
        if self.provider == "capsolver":
            return self._capsolver(url, sitekey, proxy, timeout)
        return self._twocaptcha(url, sitekey, timeout)

    def _capsolver(self, url, sitekey, proxy, timeout):
        task: dict[str, Any] = {"type": "AntiTurnstileTaskProxyLess",
                                "websiteURL": url, "websiteKey": sitekey}
        if proxy:
            task = {"type": "AntiTurnstileTask", "websiteURL": url,
                    "websiteKey": sitekey, "proxy": proxy}
        r = creq.post("https://api.capsolver.com/createTask",
                      json={"clientKey": self.api_key, "task": task}, timeout=30)
        tid = r.json().get("taskId")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3)
            res = creq.post("https://api.capsolver.com/getTaskResult",
                            json={"clientKey": self.api_key, "taskId": tid},
                            timeout=30).json()
            if res.get("status") == "ready":
                return res["solution"].get("token")
            if res.get("status") == "failed":
                log.warning("capsolver failed: %s", res.get("errorDescription"))
                return None
        return None

    def _twocaptcha(self, url, sitekey, timeout):
        r = creq.post("https://2captcha.com/in.php", data={
            "key": self.api_key, "method": "turnstile",
            "sitekey": sitekey, "pageurl": url, "json": 1}, timeout=30).json()
        if r.get("status") != 1:
            return None
        tid = r["request"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            res = creq.get("https://2captcha.com/res.php", params={
                "key": self.api_key, "action": "get", "id": tid, "json": 1}).json()
            if res.get("status") == 1:
                return res["request"]
        return None


# --------------------------------------------------------------------------- #
# 5.  L2 — headless browser solve (stealth)
# --------------------------------------------------------------------------- #
STEALTH_JS = r"""
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
window.chrome = { runtime: {}, app: { isInstalled: false } };
const gp = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function (p) {
  if (p === 37445) return 'Intel Inc.';
  if (p === 37446) return 'Intel Iris OpenGL Engine';
  return gp.call(this, p);
};
const origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (p) => (
  p.name === 'notifications'
    ? Promise.resolve({ state: Notification.permission })
    : origQuery(p)
);
"""


class BrowserSolver:
    def __init__(self, headless: bool = True, proxy: str | None = None,
                 timeout: int = 60):
        self.headless, self.proxy, self.timeout = headless, proxy, timeout

    def solve(self, url: str, wait_for_cookie: str = "cf_clearance") -> dict[str, str]:
        from playwright.sync_api import sync_playwright

        profile = STATE_DIR / f"pw_{abs(hash(url + str(self.proxy))) % 10**10}"
        with sync_playwright() as p:
            ctx = p.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled",
                      "--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-features=IsolateOrigins,site-per-process"],
                proxy={"server": self.proxy} if self.proxy else None,
                viewport={"width": 1440, "height": 900},
                locale="en-US", timezone_id="America/New_York",
            )
            ctx.add_init_script(STEALTH_JS)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto(url, wait_until="domcontentloaded",
                      timeout=self.timeout * 1000, referer="https://www.google.com/")

            # click the Turnstile checkbox if it materialises
            for sel in ('iframe[src*="challenges.cloudflare.com"]',
                        'input[type="checkbox"]', "#challenge-stage"):
                try:
                    page.wait_for_selector(sel, timeout=4000)
                    box = page.query_selector(sel)
                    if box:
                        box.click(timeout=2000)
                    break
                except Exception:
                    continue

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                if any(c["name"] == wait_for_cookie for c in ctx.cookies()):
                    break
                page.wait_for_timeout(500)

            page.wait_for_timeout(random.randint(900, 2200))  # let __cf_bm land
            cookies = {c["name"]: c["value"] for c in ctx.cookies()}
            ua = page.evaluate("navigator.userAgent")
            ctx.close()

        log.info("browser solve -> %d cookies, ua=%s", len(cookies), ua[:40])
        return cookies


# --------------------------------------------------------------------------- #
# 6.  MAIN CLIENT
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    proxies: Sequence[str] = ()
    identity_pool: Sequence[Identity] = IDENTITIES
    rps: float = 2.0
    max_attempts: int = 5
    timeout: float = 30.0
    verify: bool = True
    impersonate_native_headers: bool = True
    use_browser_fallback: bool = True
    headless: bool = True
    turnstile_api_key: str | None = None
    turnstile_provider: str = "capsolver"
    http3: bool = False
    warmup: bool = True
    persist_cookies: bool = True
    extra_fp: dict[str, Any] = field(default_factory=dict)


class GhostClient:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or Config()
        self.pool = ProxyPool(self.cfg.proxies)
        self.bucket = TokenBucket(self.cfg.rps, burst=max(2, int(self.cfg.rps)))
        self.vault = CookieVault(STATE_DIR / "cookies.json")
        self.solver = (TurnstileSolver(self.cfg.turnstile_api_key,
                                       self.cfg.turnstile_provider)
                       if self.cfg.turnstile_api_key else None)
        self._sessions: dict[tuple[str, str | None], creq.Session] = {}
        self._lock = threading.Lock()

    # -- session factory ---------------------------------------------------- #
    def _session(self, ident: Identity, proxy: str | None) -> creq.Session:
        key = (ident.name, proxy)
        with self._lock:
            if key in self._sessions:
                return self._sessions[key]
            kwargs: dict[str, Any] = {
                "impersonate": ident.impersonate,
                "proxies": ProxyPool.as_curl(proxy),
                "timeout": self.cfg.timeout,
                "verify": self.cfg.verify,
                "default_headers": self.cfg.impersonate_native_headers,
            }
            if self.cfg.extra_fp:
                kwargs["extra_fp"] = self.cfg.extra_fp
            if self.cfg.http3 and CurlHttpVersion is not None:
                kwargs["http_version"] = CurlHttpVersion.V3
            s = creq.Session(**kwargs)
            self._sessions[key] = s
            return s

    def _inject_browser_cookies(self, session, cookies: Mapping[str, str],
                                host: str) -> None:
        for name, value in cookies.items():
            try:
                session.cookies.set(name, value, domain=host, path="/")
            except Exception:
                pass

    # -- core --------------------------------------------------------------- #
    def request(self, method: str, url: str, *, kind: str = "navigate",
                referer: str | None = None, **kw) -> creq.Response:
        host = urlparse(url).netloc
        last_exc: Exception | None = None

        for attempt in range(self.cfg.max_attempts):
            ident = self.cfg.identity_pool[
                (attempt + random.randrange(len(self.cfg.identity_pool)))
                % len(self.cfg.identity_pool)]
            proxy = self.pool.for_identity(ident.name, attempt)
            session = self._session(ident, proxy)

            if self.cfg.persist_cookies:
                self.vault.load_into(session, ident.name, proxy, host)

            # --- L0 / L1: impersonated request ----------------------------- #
            try:
                time.sleep(self.bucket.take())
                headers = dict(fetch_metadata(kind, url, referer))
                headers.update(kw.pop("headers", {}) or {})
                resp = session.request(method, url, headers=headers,
                                       allow_redirects=True, **kw)
            except Exception as exc:                      # network / TLS reset
                last_exc = exc
                log.warning("attempt %d network error: %s", attempt, exc)
                time.sleep(min(2 ** attempt, 8) + random.random())
                continue

            verdict, meta = classify(resp)
            log.info("attempt=%d identity=%s status=%s verdict=%s ray=%s",
                     attempt, ident.name, resp.status_code, verdict.name,
                     meta.get("cf_ray"))

            if verdict is Verdict.OK:
                if self.cfg.persist_cookies:
                    self.vault.save_from(session, ident.name, proxy, host)
                return resp

            if self.cfg.persist_cookies:
                self.vault.save_from(session, ident.name, proxy, host)

            # --- L3: Turnstile -> external solver -------------------------- #
            if verdict is Verdict.TURNSTILE and self.solver and meta.get("sitekey"):
                token = self.solver.solve(url, meta["sitekey"], proxy)
                if token:
                    try:
                        session.cookies.set("cf_clearance", token, domain=host,
                                            path="/")
                    except Exception:
                        pass

            # --- L2: browser solve ----------------------------------------- #
            elif verdict in (Verdict.JS_CHALLENGE, Verdict.HARD_BLOCK) \
                    and self.cfg.use_browser_fallback and attempt >= 1:
                try:
                    cookies = BrowserSolver(self.cfg.headless, proxy).solve(url)
                    self._inject_browser_cookies(session, cookies, host)
                    if self.cfg.persist_cookies:
                        self.vault.save_from(session, ident.name, proxy, host)
                except Exception as exc:
                    log.warning("browser solve failed: %s", exc)

            # backoff: jittered, escalating, never uniform
            sleep = min(1.5 * (2 ** attempt), 20) * (0.6 + random.random() * 0.8)
            if verdict is Verdict.RATE_LIMIT:
                sleep = max(sleep, 5.0)
            time.sleep(sleep)

        if last_exc:
            raise last_exc
        raise RuntimeError(f"exhausted {self.cfg.max_attempts} attempts on {url}")

    # -- convenience -------------------------------------------------------- #
    def warmup(self, origin: str) -> None:
        """Hit the root first so __cf_bm / cf_clearance exist before the API call."""
        if not self.cfg.warmup:
            return
        try:
            self.request("GET", origin, kind="navigate")
            time.sleep(random.uniform(0.4, 1.3))
        except Exception as exc:
            log.debug("warmup skipped: %s", exc)

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def post_json(self, url: str, payload: Any, referer: str | None = None, **kw):
        return self.request("POST", url, kind="xhr", referer=referer,
                            json=payload, **kw)

    def close(self) -> None:
        for s in self._sessions.values():
            try:
                s.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# 7.  CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Advanced Cloudflare/WAF bypass fetch")
    ap.add_argument("url")
    ap.add_argument("-X", "--method", default="GET")
    ap.add_argument("--proxy", action="append", default=[],
                    help="repeatable; use sticky residential/session proxies")
    ap.add_argument("--rps", type=float, default=2.0)
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--http3", action="store_true")
    ap.add_argument("--capsolver", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    cfg = Config(
        proxies=a.proxy, rps=a.rps, max_attempts=a.attempts,
        use_browser_fallback=not a.no_browser, headless=not a.headed,
        turnstile_api_key=a.capsolver, http3=a.http3,
    )
    client = GhostClient(cfg)
    try:
        parsed = urlparse(a.url)
        client.warmup(f"{parsed.scheme}://{parsed.netloc}/")
        resp = client.request(a.method, a.url)
        print(f"HTTP {resp.status_code}  len={len(resp.content)}  "
              f"cf-ray={resp.headers.get('cf-ray')}")
        text = resp.text
        if a.out:
            Path(a.out).write_text(text)
        else:
            print(text[:3000])
    finally:
        client.close()


if __name__ == "__main__":
    main()