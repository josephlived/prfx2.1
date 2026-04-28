from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, Iterator, List

from models import WhoisRecord

try:
    from ipwhois import IPWhois  # type: ignore
except ImportError:  # pragma: no cover
    IPWhois = None


REGISTRY_DOMAIN_SUFFIXES = (
    "arin.net",
    "ripe.net",
    "apnic.net",
    "afrinic.net",
    "lacnic.net",
    "jpnic.net",
    "krnic.net",
    "twnic.tw",
    "iana.org",
    "icann.org",
    "rdap.org",
    "in-addr.arpa",
    "ip6.arpa",
)


def _is_registry_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in REGISTRY_DOMAIN_SUFFIXES)


def _collect_vcard_names(vcard: Iterable[Any]) -> List[str]:
    names: List[str] = []
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = item[0]
        value = item[3]
        if key in {"fn", "org"} and isinstance(value, str):
            names.append(value.strip())
    return names


def _collect_vcard_emails(vcard: Iterable[Any]) -> List[str]:
    emails: List[str] = []
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == "email" and isinstance(item[3], str):
            emails.append(item[3].strip())
    return emails


def _collect_vcard_urls(vcard: Iterable[Any]) -> List[str]:
    urls: List[str] = []
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == "url" and isinstance(item[3], str):
            urls.append(item[3].strip())
    return urls


def _flatten_address_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            flattened = _flatten_address_value(item)
            if flattened:
                parts.append(flattened)
        return " ".join(parts)
    if isinstance(value, dict):
        parts = []
        for key in ("label", "value"):
            flattened = _flatten_address_value(value.get(key))
            if flattened:
                parts.append(flattened)
        return " ".join(parts)
    return ""


def _clean_address(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.replace("\\n", " ").replace("\n", " ")).strip(" ,")
    return cleaned


def _collect_vcard_addresses(vcard: Iterable[Any]) -> List[str]:
    addresses: List[str] = []
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == "adr":
            address = _clean_address(_flatten_address_value(item[3]))
            if address:
                addresses.append(address)
    return addresses


def _collect_remarks_text(remarks: Any) -> List[str]:
    texts: List[str] = []
    if not isinstance(remarks, list):
        return texts
    for item in remarks:
        if not isinstance(item, dict):
            continue
        title = item.get("title")
        if isinstance(title, str):
            texts.append(title)
        description = item.get("description")
        if isinstance(description, list):
            for desc in description:
                if isinstance(desc, str):
                    texts.append(desc)
        elif isinstance(description, str):
            texts.append(description)
    return texts


def _walk_strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_strings(item)


def _extract_org_names(rdap: dict[str, Any]) -> List[str]:
    names: List[str] = []
    objects = rdap.get("objects") or {}
    for obj in objects.values():
        if not isinstance(obj, dict):
            continue
        contact = obj.get("contact") or {}
        if isinstance(contact.get("name"), str):
            names.append(contact["name"])
        vcard = contact.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            names.extend(_collect_vcard_names(vcard[1]))
        vcard = obj.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            names.extend(_collect_vcard_names(vcard[1]))
    unique = []
    seen = set()
    for name in names:
        stripped = name.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            unique.append(stripped)
    return unique


def _extract_addresses(rdap: dict[str, Any]) -> List[str]:
    addresses: List[str] = []
    objects = rdap.get("objects") or {}
    for obj in objects.values():
        if not isinstance(obj, dict):
            continue
        contact = obj.get("contact") or {}
        if isinstance(contact, dict):
            raw_address = contact.get("address")
            if isinstance(raw_address, list):
                for item in raw_address:
                    address = _clean_address(_flatten_address_value(item))
                    if address:
                        addresses.append(address)
            elif isinstance(raw_address, str):
                address = _clean_address(raw_address)
                if address:
                    addresses.append(address)
            vcard = contact.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                addresses.extend(_collect_vcard_addresses(vcard[1]))
        vcard = obj.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            addresses.extend(_collect_vcard_addresses(vcard[1]))

    unique: List[str] = []
    seen = set()
    for address in addresses:
        stripped = address.strip()
        key = stripped.lower()
        if stripped and key not in seen:
            seen.add(key)
            unique.append(stripped)
    return unique


def _extract_domains(rdap: dict[str, Any], org_names: List[str], net_name: str) -> List[str]:
    candidates: List[str] = []
    candidates.extend(org_names)
    if net_name:
        candidates.append(net_name)
    network = rdap.get("network") or {}
    if isinstance(network, dict):
        for key in ("name", "handle"):
            value = network.get(key)
            if isinstance(value, str):
                candidates.append(value)
        candidates.extend(_collect_remarks_text(network.get("remarks")))
    objects = rdap.get("objects") or {}
    for obj in objects.values():
        if not isinstance(obj, dict):
            continue
        contact = obj.get("contact") or {}
        for vcard in (contact.get("vcardArray"), obj.get("vcardArray")):
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                candidates.extend(_collect_vcard_emails(vcard[1]))
                candidates.extend(_collect_vcard_urls(vcard[1]))
        candidates.extend(_collect_remarks_text(obj.get("remarks")))
    candidates.extend(_walk_strings(rdap))
    domains: List[str] = []
    seen = set()

    def _add_domain(value: str) -> None:
        value = value.strip(".")
        if not value or value in seen or _is_registry_domain(value):
            return
        seen.add(value)
        domains.append(value)

    for candidate in candidates:
        for domain in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", str(candidate).lower()):
            _add_domain(domain)
            if domain.startswith("www."):
                _add_domain(domain[4:])
    return domains


def _extract_registry_name(rdap: dict[str, Any]) -> str:
    for key in ("asn_registry", "nir"):
        value = rdap.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    network = rdap.get("network") or {}
    links = network.get("links") if isinstance(network, dict) else None
    if isinstance(links, list):
        for link in links:
            if not isinstance(link, dict):
                continue
            href = str(link.get("href", "")).lower()
            for registry_name in ("arin", "ripe", "apnic", "afrinic", "lacnic", "jpnic", "krnic"):
                if registry_name in href:
                    return registry_name.upper()
    return ""


class WhoisLookupClient:
    def __init__(self, cache_dir: str | Path = "cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "whois_cache.json"

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover
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

    def is_available(self) -> bool:
        return IPWhois is not None

    def lookup(self, prefix: str) -> WhoisRecord:
        normalized_prefix = prefix.strip()
        cache = self._load_cache()
        cached_record = cache.get(normalized_prefix)
        if isinstance(cached_record, dict):
            return WhoisRecord(
                prefix=normalized_prefix,
                org_names=list(cached_record.get("org_names", [])),
                net_name=str(cached_record.get("net_name", "")),
                domains=list(cached_record.get("domains", [])),
                addresses=list(cached_record.get("addresses", [])),
                source_url=str(cached_record.get("source_url", "")),
                error=str(cached_record.get("error", "")),
                cached=True,
                registry=str(cached_record.get("registry", "")),
            )
        if IPWhois is None:
            return WhoisRecord(prefix=normalized_prefix, error="ipwhois is not installed.")
        base_ip = normalized_prefix.split("/", 1)[0].strip()
        try:
            rdap = IPWhois(base_ip).lookup_rdap(depth=1)
            network = rdap.get("network") or {}
            org_names = _extract_org_names(rdap)
            net_name = ""
            if isinstance(network.get("name"), str):
                net_name = network["name"].strip()
            domains = _extract_domains(rdap, org_names, net_name)
            addresses = _extract_addresses(rdap)
            source_url = ""
            if isinstance(rdap.get("nir"), str):
                source_url = rdap["nir"]
            record = WhoisRecord(
                prefix=normalized_prefix,
                org_names=org_names,
                net_name=net_name,
                domains=domains,
                addresses=addresses,
                source_url=source_url,
                registry=_extract_registry_name(rdap),
            )
            cache[normalized_prefix] = asdict(record)
            self._save_cache(cache)
            return record
        except Exception as exc:  # pragma: no cover
            record = WhoisRecord(prefix=normalized_prefix, error=str(exc))
            cache[normalized_prefix] = asdict(record)
            self._save_cache(cache)
            return record
