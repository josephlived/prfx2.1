from __future__ import annotations

import html
import json
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from matching import normalize_address, normalize_domain

try:
    from playwright.sync_api import BrowserContext, sync_playwright  # type: ignore
except ImportError:  # pragma: no cover
    BrowserContext = Any  # type: ignore
    sync_playwright = None


USER_AGENT = "PrefixWorkbench/1.0 (+https://local.app)"
COMMON_PATHS = [
    "",
    "/contact",
    "/contact-us",
    "/locations",
    "/location",
    "/office-locations",
    "/our-locations",
    "/about",
    "/about-us",
    "/company",
]
KEYWORD_HINTS = ("location", "locations", "office", "contact", "about", "company", "investor")


class DomainEvidenceClient:
    def __init__(self, cache_dir: str | Path = "cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "domain_page_cache.json"

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self, cache_data: dict[str, Any]) -> None:
        self.cache_path.write_text(json.dumps(cache_data, indent=2, ensure_ascii=True), encoding="utf-8")

    def clear_cache(self) -> None:
        if self.cache_path.exists():
            self.cache_path.unlink()

    def cache_stats(self) -> dict[str, Any]:
        cache = self._load_cache()
        return {
            "entries": len(cache),
            "path": str(self.cache_path),
        }

    def browser_available(self) -> bool:
        return sync_playwright is not None

    def engine_label(self) -> str:
        return "Playwright (Chromium)" if self.browser_available() else "HTTP fallback"

    @contextmanager
    def _browser_session(self) -> Iterator[Optional[BrowserContext]]:
        if sync_playwright is None:
            yield None
            return
        playwright = None
        browser = None
        context = None
        try:
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(user_agent=USER_AGENT, ignore_https_errors=True)
            yield context
        except Exception:
            yield None
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if playwright is not None:
                try:
                    playwright.stop()
                except Exception:
                    pass

    def _fetch_url_http(self, url: str) -> dict[str, Any]:
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=12) as response:
                content_type = response.headers.get("Content-Type", "")
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset, errors="ignore")
        except Exception as exc:
            return {"ok": False, "content_type": "", "normalized_text": "", "links": [], "error": str(exc)}

        links: List[str] = []
        normalized_text = ""
        if "xml" in content_type or url.endswith("sitemap.xml"):
            links = self._extract_sitemap_links(body)
        else:
            normalized_text = self._extract_normalized_text(body)
            links = self._extract_links(body, url)

        return {
            "ok": True,
            "content_type": content_type,
            "normalized_text": normalized_text,
            "links": links,
            "error": "",
        }

    def _fetch_url_browser(self, url: str, browser_context: BrowserContext) -> dict[str, Any]:
        page = browser_context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1200)
            body = page.content()
            final_url = page.url
            links = self._extract_links(body, final_url)
            return {
                "ok": True,
                "content_type": "text/html",
                "normalized_text": self._extract_normalized_text(body),
                "links": links,
                "error": "",
            }
        except Exception as exc:
            return {"ok": False, "content_type": "", "normalized_text": "", "links": [], "error": str(exc)}
        finally:
            try:
                page.close()
            except Exception:
                pass

    def _fetch_url(self, url: str, browser_context: Optional[BrowserContext] = None) -> dict[str, Any]:
        cache = self._load_cache()
        cached = cache.get(url)
        if isinstance(cached, dict):
            return cached
        record = self._fetch_url_browser(url, browser_context) if browser_context is not None else self._fetch_url_http(url)
        if not record.get("ok") and browser_context is not None:
            record = self._fetch_url_http(url)
        cache[url] = record
        self._save_cache(cache)
        return record

    def _extract_sitemap_links(self, xml_text: str) -> List[str]:
        links: List[str] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return links
        for element in root.iter():
            tag = element.tag.lower()
            if tag.endswith("loc") and element.text:
                url = element.text.strip()
                lower_url = url.lower()
                if any(keyword in lower_url for keyword in KEYWORD_HINTS):
                    links.append(url)
        return links

    def _extract_links(self, html_text: str, base_url: str) -> List[str]:
        links: List[str] = []
        for raw_link in re.findall(r'href=["\']([^"\']+)["\']', html_text, flags=re.IGNORECASE):
            url = urljoin(base_url, raw_link.strip())
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                continue
            if any(keyword in parsed.path.lower() for keyword in KEYWORD_HINTS):
                links.append(url)
        deduped: List[str] = []
        seen = set()
        for link in links:
            if link not in seen:
                seen.add(link)
                deduped.append(link)
        return deduped

    def _extract_normalized_text(self, html_text: str) -> str:
        stripped = re.sub(r"(?is)<script.*?>.*?</script>", " ", html_text)
        stripped = re.sub(r"(?is)<style.*?>.*?</style>", " ", stripped)
        stripped = re.sub(r"(?s)<[^>]+>", " ", stripped)
        stripped = html.unescape(stripped)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        return normalize_address(stripped)

    def _candidate_urls(self, domain: str, browser_context: Optional[BrowserContext] = None) -> List[str]:
        canonical_domain = normalize_domain(domain)
        base_urls = [
            f"https://{canonical_domain}",
            f"https://www.{canonical_domain}",
            f"http://{canonical_domain}",
        ]
        candidates: List[str] = []
        for base_url in base_urls:
            candidates.extend(f"{base_url}{path}" for path in COMMON_PATHS)
            sitemap_url = f"{base_url}/sitemap.xml"
            sitemap_record = self._fetch_url(sitemap_url, browser_context=browser_context)
            if sitemap_record.get("ok"):
                candidates.extend(sitemap_record.get("links", []))
            homepage_record = self._fetch_url(base_url, browser_context=browser_context)
            if homepage_record.get("ok"):
                candidates.extend(homepage_record.get("links", []))

        deduped: List[str] = []
        seen = set()
        for url in candidates:
            if not isinstance(url, str):
                continue
            parsed = urlparse(url)
            parsed_domain = normalize_domain(parsed.netloc)
            if parsed_domain != canonical_domain and parsed_domain != f"www.{canonical_domain}":
                continue
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped[:14]

    def find_address_evidence(self, domains: Iterable[str], address: str) -> Optional[str]:
        normalized_address = normalize_address(address)
        if not normalized_address:
            return None
        with self._browser_session() as browser_context:
            for domain in domains:
                for url in self._candidate_urls(domain, browser_context=browser_context):
                    page_record = self._fetch_url(url, browser_context=browser_context)
                    if not page_record.get("ok"):
                        continue
                    normalized_text = str(page_record.get("normalized_text", ""))
                    if normalized_address and normalized_address in normalized_text:
                        return url
        return None

    def diagnose_domains(self, domains: Iterable[str]) -> List[str]:
        issues: List[str] = []
        with self._browser_session() as browser_context:
            for domain in domains:
                urls = self._candidate_urls(domain, browser_context=browser_context)
                if not urls:
                    issues.append(f"{domain}: no candidate pages discovered")
                    continue
                domain_errors: List[str] = []
                successes = 0
                for url in urls[:5]:
                    page_record = self._fetch_url(url, browser_context=browser_context)
                    if page_record.get("ok"):
                        successes += 1
                    else:
                        error = str(page_record.get("error", "")).strip()
                        if error:
                            domain_errors.append(error)
                if successes == 0 and domain_errors:
                    issues.append(f"{domain}: {domain_errors[0]}")
        return issues
