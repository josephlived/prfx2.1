from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from matching import normalize_address, normalize_company_name, normalize_domain


USER_AGENT = "PrefixWorkbench/1.0 (+https://local.app)"
SEARCH_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
MAX_SEARCH_QUERIES = 3
MAX_PAGE_FETCHES = 3

DIRECTION_TOKENS = {
    "north",
    "south",
    "east",
    "west",
    "northeast",
    "northwest",
    "southeast",
    "southwest",
}

STREET_TYPE_TOKENS = {
    "street",
    "road",
    "avenue",
    "boulevard",
    "drive",
    "circle",
    "parkway",
    "center",
    "suite",
    "floor",
    "highway",
    "freeway",
    "way",
    "court",
    "lane",
    "place",
    "terrace",
    "trail",
    "plaza",
    "plz",
    "square",
    "route",
    "pike",
    "turnpike",
    "alley",
    "row",
}

LOCATION_NOISE_TOKENS = {"customer", "client", "site", "masergy"}

UNIT_DESIGNATOR_PATTERN = re.compile(
    r"\b(?:suite|ste|floor|fl|unit|apt|apartment|room|rm|building|bldg)\s+\w{1,6}\b"
)

COUNTRY_SUFFIX_PATTERN = re.compile(
    r"[\s,]*(?:u\.?s\.?a?\.?|united states(?:\s+of\s+america)?)\.?\s*$",
    re.IGNORECASE,
)


def _url_matches_accepted_domains(url: str, accepted_domains: Iterable[str]) -> bool:
    accepted = [normalize_domain(domain) for domain in accepted_domains if normalize_domain(domain)]
    if not accepted:
        return True
    hostname = normalize_domain(urlparse(url).netloc)
    if not hostname:
        return False
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in accepted)


class BraveSearchClient:
    def __init__(self, api_key: str = "", cache_dir: str | Path = "cache") -> None:
        self.api_key = api_key.strip()
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "search_cache.json"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def engine_label(self) -> str:
        return "Brave Search API" if self.is_configured() else "Disabled"

    def validate_key(self) -> Tuple[bool, str]:
        if not self.is_configured():
            return False, "No Brave Search API key is configured."
        _, error = self._search("assurant office locations")
        if error:
            return False, error
        return True, "Brave Search API key is working."

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self, cache_data: dict[str, Any]) -> None:
        self.cache_path.write_text(json.dumps(cache_data, indent=2, ensure_ascii=True), encoding="utf-8")

    def cache_stats(self) -> dict[str, Any]:
        cache = self._load_cache()
        return {
            "entries": len(cache),
            "path": str(self.cache_path),
        }

    def clear_cache(self) -> None:
        if self.cache_path.exists():
            self.cache_path.unlink()

    def _cache_get(self, key: str) -> Optional[dict[str, Any]]:
        cache = self._load_cache()
        value = cache.get(key)
        return value if isinstance(value, dict) else None

    def _cache_put(self, key: str, value: dict[str, Any]) -> None:
        cache = self._load_cache()
        cache[key] = value
        self._save_cache(cache)

    def _search(self, query: str) -> Tuple[List[dict[str, Any]], str]:
        cache_key = f"search::{query}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return list(cached.get("results", [])), str(cached.get("error", ""))
        if not self.is_configured():
            return [], "Brave Search API key is not configured."
        params = urlencode({"q": query, "count": 10})
        request = Request(
            f"{SEARCH_ENDPOINT}?{params}",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "X-Subscription-Token": self.api_key,
            },
        )
        try:
            with urlopen(request, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        except Exception as exc:
            self._cache_put(cache_key, {"results": [], "error": str(exc)})
            return [], str(exc)
        results = payload.get("web", {}).get("results", []) if isinstance(payload, dict) else []
        normalized_results = []
        for item in results:
            if not isinstance(item, dict):
                continue
            normalized_results.append(
                {
                    "title": str(item.get("title", "")),
                    "description": str(item.get("description", "")),
                    "url": str(item.get("url", "")),
                }
            )
        self._cache_put(cache_key, {"results": normalized_results, "error": ""})
        return normalized_results, ""

    def _fetch_page(self, url: str) -> Tuple[str, str]:
        cache_key = f"page::{url}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return str(cached.get("normalized_text", "")), str(cached.get("error", ""))
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=6) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset, errors="ignore")
        except Exception as exc:
            self._cache_put(cache_key, {"normalized_text": "", "error": str(exc)})
            return "", str(exc)
        body = re.sub(r"(?is)<script.*?>.*?</script>", " ", body)
        body = re.sub(r"(?is)<style.*?>.*?</style>", " ", body)
        body = re.sub(r"(?s)<[^>]+>", " ", body)
        body = html.unescape(body)
        body = re.sub(r"\s+", " ", body).strip()
        normalized = normalize_address(body)
        self._cache_put(cache_key, {"normalized_text": normalized, "error": ""})
        return normalized, ""

    def _location_tokens(self, address: str) -> Tuple[str, str]:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return "", ""
        country = tokens[-1]
        state = ""
        search_tokens = tokens[:-1] if country == "us" else tokens
        for token in reversed(search_tokens):
            if len(token) == 2 and token.isalpha():
                state = token
                break
        return state, country

    def _city_tokens(self, address: str) -> str:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return ""
        search_tokens = tokens[:-1] if tokens[-1] == "us" else tokens
        state_index = -1
        for index in range(len(search_tokens) - 1, -1, -1):
            token = search_tokens[index]
            if len(token) == 2 and token.isalpha():
                state_index = index
                break
        if state_index <= 0:
            return ""
        before_state = search_tokens[:state_index]
        last_street_index = -1
        for index, token in enumerate(before_state):
            if token in STREET_TYPE_TOKENS:
                last_street_index = index
        city_source = before_state[last_street_index + 1 :]
        city_tokens = [
            token
            for token in city_source
            if not token.isdigit() and token not in DIRECTION_TOKENS and token not in LOCATION_NOISE_TOKENS
        ]
        return " ".join(city_tokens[-2:]).strip()

    def _postal_token(self, address: str) -> str:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return ""
        search_tokens = tokens[:-1] if tokens[-1] == "us" else tokens
        for token in reversed(search_tokens):
            if token.isdigit() and len(token) >= 5:
                return token
        return ""

    def _address_query_variant(self, address: str) -> str:
        cleaned = address.strip().rstrip(",.;: ")
        cleaned = COUNTRY_SUFFIX_PATTERN.sub("", cleaned).strip().rstrip(",.;:")
        return cleaned

    def _company_in_snippet(self, snippet_text: str, company_name: str) -> bool:
        if not snippet_text or not company_name.strip():
            return False
        padded = f" {snippet_text} "
        variants = {
            normalize_company_name(company_name),
            normalize_company_name(company_name, remove_suffixes=True),
            normalize_company_name(company_name, remove_suffixes=True, remove_articles=True),
        }
        return any(v and f" {v} " in padded for v in variants)

    def _any_company_in_text(self, text: str, company_names: Iterable[str]) -> bool:
        return any(self._company_in_snippet(text, company_name) for company_name in company_names)

    def _snippet_match_mode(
        self,
        snippet_text: str,
        normalized_address: str,
        company_name: str,
        city: str,
        state: str,
        country: str,
    ) -> str:
        if self._addresses_equivalent(snippet_text, normalized_address):
            return "exact_address"
        location_hit = False
        if country == "us":
            if state and f" {state} " in f" {snippet_text} ":
                location_hit = True
        elif country and f" {country} " in f" {snippet_text} ":
            location_hit = True
        if location_hit and city and f" {city} " not in f" {snippet_text} ":
            location_hit = False
        if location_hit and self._company_in_snippet(snippet_text, company_name):
            return "state_country"
        return ""

    def _strip_unit_designators(self, text: str) -> str:
        if not text:
            return text
        cleaned = UNIT_DESIGNATOR_PATTERN.sub(" ", text)
        return re.sub(r"\s+", " ", cleaned).strip()

    def _addresses_equivalent(self, haystack_text: str, normalized_address: str) -> bool:
        if not normalized_address:
            return False
        if normalized_address in haystack_text:
            return True
        short_address = normalized_address
        if short_address.endswith(" us"):
            short_address = short_address[:-3].strip()
        if short_address and short_address in haystack_text:
            return True
        cleaned_haystack = self._strip_unit_designators(haystack_text)
        cleaned_address = self._strip_unit_designators(short_address)
        if cleaned_address and cleaned_address in cleaned_haystack:
            return True
        return False

    def find_address_evidence(
        self,
        company_name: str,
        address: str,
        accepted_domains: Iterable[str],
        related_company_names: Iterable[str] = (),
    ) -> Tuple[Optional[str], str, str, str]:
        accepted_domain_list = [normalize_domain(domain) for domain in accepted_domains if normalize_domain(domain)]
        snippet_trust_enabled = bool(accepted_domain_list)
        normalized_address = normalize_address(address)
        if not normalized_address:
            return None, "", "No usable address was available for live search.", ""
        company_names: List[str] = []
        seen_company_names = set()
        for candidate_name in [company_name, *related_company_names]:
            normalized_candidate = normalize_company_name(candidate_name)
            if normalized_candidate and normalized_candidate not in seen_company_names:
                seen_company_names.add(normalized_candidate)
                company_names.append(candidate_name)
        state, country = self._location_tokens(address)
        city = self._city_tokens(address)
        postal = self._postal_token(address)
        address_variant = self._address_query_variant(address)
        queries: List[str] = []
        seen_queries: set[str] = set()

        def _add_query(query: str) -> None:
            if query and query not in seen_queries:
                seen_queries.add(query)
                queries.append(query)

        for candidate_name in company_names:
            if country == "us" and address_variant:
                _add_query(f"\"{candidate_name}\" \"{address_variant}\"")
            else:
                _add_query(f"\"{candidate_name}\" \"{address}\"")
                if address_variant:
                    _add_query(f"\"{candidate_name}\" \"{address_variant}\"")
            if city and state and postal:
                _add_query(f"\"{candidate_name}\" \"{city}\" \"{state}\" \"{postal}\"")
            elif city and state:
                _add_query(f"\"{candidate_name}\" \"{city}\" \"{state}\"")
        queries = queries[:MAX_SEARCH_QUERIES]
        seen_urls = set()
        last_error = ""
        debug_lines: List[str] = []
        fallback_state_country: Optional[Tuple[str, str]] = None
        page_fetches = 0
        for query in queries:
            results, error = self._search(query)
            if error:
                last_error = error
                debug_lines.append(f"query={query} error={error}")
                continue
            debug_lines.append(f"query={query} results={len(results)}")
            for item in results:
                url = str(item.get("url", "")).strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                snippet_text = normalize_address(f"{item.get('title', '')} {item.get('description', '')}")
                debug_lines.append(f"url={url} snippet={snippet_text[:220]}")
                on_accepted_domain = _url_matches_accepted_domains(url, accepted_domain_list)
                if accepted_domain_list and not on_accepted_domain:
                    external_mode = ""
                    for candidate_name in company_names or [company_name]:
                        external_mode = self._snippet_match_mode(
                            snippet_text,
                            normalized_address,
                            candidate_name,
                            city,
                            state,
                            country,
                        )
                        if external_mode:
                            break
                    if external_mode == "state_country" and fallback_state_country is None and not accepted_domain_list:
                        fallback_state_country = (url, "state_country")
                        debug_lines.append(f"external_state_country_candidate={url}")
                    else:
                        debug_lines.append(f"skipped_non_accepted_domain={url}")
                    continue
                if not accepted_domain_list:
                    external_snippet_mode = ""
                    for candidate_name in company_names or [company_name]:
                        external_snippet_mode = self._snippet_match_mode(
                            snippet_text,
                            normalized_address,
                            candidate_name,
                            city,
                            state,
                            country,
                        )
                        if external_snippet_mode and self._company_in_snippet(snippet_text, candidate_name):
                            break
                        external_snippet_mode = ""
                    if external_snippet_mode:
                        debug_lines.append(f"external_snippet_match={external_snippet_mode} url={url}")
                        return url, external_snippet_mode, "", "\n".join(debug_lines)
                if snippet_trust_enabled:
                    snippet_mode = ""
                    for candidate_name in company_names or [company_name]:
                        snippet_mode = self._snippet_match_mode(
                            snippet_text,
                            normalized_address,
                            candidate_name,
                            city,
                            state,
                            country,
                        )
                        if snippet_mode:
                            break
                    if snippet_mode:
                        debug_lines.append(f"snippet_match={snippet_mode} url={url}")
                        return url, snippet_mode, "", "\n".join(debug_lines)
                if page_fetches >= MAX_PAGE_FETCHES:
                    debug_lines.append(f"skipped_page_fetch_limit={url}")
                    continue
                page_fetches += 1
                normalized_page, fetch_error = self._fetch_page(url)
                if fetch_error:
                    snippet_mode = ""
                    for candidate_name in company_names or [company_name]:
                        snippet_mode = self._snippet_match_mode(
                            snippet_text,
                            normalized_address,
                            candidate_name,
                            city,
                            state,
                            country,
                        )
                        if snippet_mode:
                            break
                    if snippet_mode:
                        debug_lines.append(f"snippet_match_after_fetch_error={snippet_mode} url={url}")
                        return url, snippet_mode, "", "\n".join(debug_lines)
                    last_error = fetch_error
                    debug_lines.append(f"fetch_error={url} error={fetch_error}")
                    continue
                if self._addresses_equivalent(normalized_page, normalized_address):
                    if not accepted_domain_list and not self._any_company_in_text(normalized_page, company_names or [company_name]):
                        debug_lines.append(f"external_page_address_without_company={url}")
                        continue
                    debug_lines.append(f"page_match=exact_address url={url}")
                    return url, "exact_address", "", "\n".join(debug_lines)
                location_hit = False
                if country == "us":
                    if state and f" {state} " in f" {normalized_page} ":
                        location_hit = True
                elif country and f" {country} " in f" {normalized_page} ":
                    location_hit = True
                if location_hit and city and f" {city} " not in f" {normalized_page} ":
                    location_hit = False
                if location_hit and self._any_company_in_text(normalized_page, company_names or [company_name]):
                    debug_lines.append(f"page_match=state_country url={url}")
                    return url, "state_country", "", "\n".join(debug_lines)
                snippet_mode = ""
                for candidate_name in company_names or [company_name]:
                    snippet_mode = self._snippet_match_mode(
                        snippet_text,
                        normalized_address,
                        candidate_name,
                        city,
                        state,
                        country,
                    )
                    if snippet_mode:
                        break
                if snippet_mode:
                    debug_lines.append(f"snippet_match_post_page={snippet_mode} url={url}")
                    return url, snippet_mode, "", "\n".join(debug_lines)
        if fallback_state_country:
            url, mode = fallback_state_country
            debug_lines.append(f"external_state_country_accepted={url}")
            return url, mode, "", "\n".join(debug_lines)
        return None, "", last_error or "Live search did not find address or location evidence on the searched pages.", "\n".join(debug_lines)
