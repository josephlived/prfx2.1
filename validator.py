from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

import pandas as pd

from address_evidence_cache import AddressEvidenceCache
from matching import (
    classify_company_match,
    clean_company_name,
    find_address_match,
    is_private_address,
    is_usable_address,
    normalize_address,
    normalize_company_name,
    parse_address_evidence,
    parse_alias_lines,
    parse_company_lines,
    parse_domain_lines,
    strip_netname_prefix,
)
from models import CompanyCatalog, InputRow, ValidationResult, WhoisOnlyResult
from domain_crawler import DomainEvidenceClient
from live_search import SEARCH_NOT_FOUND, BraveSearchClient
from whois_lookup import WhoisLookupClient


@dataclass
class WhoisMatchEvaluation:
    matched_name: str = ""
    match_type: str = "no_match"
    match_score: int = 0
    org_display: str = ""
    net_display: str = ""
    domain_display: str = ""
    address_display: str = ""
    registry_display: str = ""
    error: str = ""
    domain_matched: bool = False
    name_kind: str = "none"


KNOWN_DATA_CENTER_ADDRESSES = {
    normalize_address(value)
    for value in [
        "268 Bush St San Francisco, CA 94104 US",
        "2701 W 15th St PMB 236 Plano, TX 75075 US",
        "5000 Walzem Rd. San Antonio, TX 78218 US",
        "34 St Martin Drive Marlborough, MA 01752 US",
        "1649 Frankford Rd. West, Carrollton, TX, 75007, United States",
        "21711 Filigree Court Ashburn, VA 20147 US",
        "1950 N Stemmons Freeway, Dallas, TX, 75207, United States",
        "3030 Corvin Dr Santa Clara, CA 95051 US",
        "401 N Broad St Philadelphia PA 19106 US",
        "777 Central Boulevard, Carlstadt, NJ, USA",
        "350 East Cermak Chicago, IL",
        "20 Black Fan Road, Welwyn Garden City, Hertfordshire, UK",
        "11 Great Oaks Blvd San Jose CA 95119 US",
        "3800 N Central Ave Phoenix, Arizona",
        "15 Shattuck Road Andover, MA 01810 US",
        "21110 Ridgetop Cir Sterling, VA",
        "2323 Bryan Floor 26 Dallas, TX",
        "Toyosu 6-2-15, Koto-ku Tokyo, 135-0061 JP",
        "DC 2 Nodia Net Magic Data Centre H 223 Sector 63 Gautam Budh Nagar Nodia 201301 Noida Uttar Pradesh",
        "1/18 STT Global DataCentres India Private Limited TCL VSB Ultadanga CIT Scheme VII M Kolkata 700054 Kolkata West Bengal",
        "6431 Longhorn Drive Irving TX 75063 US",
        "1033 Jefferson St NW Atlanta GA 30318 US",
        "350 East Cermak Chicago IL 60610 US",
        "56 Marietta St NW Atlanta GA 30303 US",
        "11650 Great Oaks Way Alpharetta GA 30022-2408 US",
        "12098 Sunrise Valley Dr Reston VA US",
        "26A Ayer Rajah Crescent, Singapore 139963",
        "2805 Diehl Rd Aurora IL 60502 US",
        "9333 Grand Ave Franklin Park IL 60131 US",
        "6327 NE Evergreen Pkwy - Bldg C, Hillsboro, OR",
        "14100 Park Vista Boulevard, Fort Worth, TX",
        "2681 Kelvin Ave Irvine CA",
        "6000 Technology Blvd Sandston VA",
        "One Federal Street Boston MA",
        "8025 I.H. 35 North Austin TX",
        "800 N Central Ave Phoenix, Arizona",
        "50 East Cermak Chicago, IL",
        "950 N Stemmons Freeway, Dallas, TX, 75207, United States",
        "711 N Edgewood Ave, Wood Dale, IL, United States",
        "1905 Lunt Avenue, Elk Grove Village, IL, USA",
        "2-2-43, Higashi-Shinagawa, 140-0002 (T1 Building), Tokyo, Japan",
    ]
}

HEADER_ALIASES = {"analyst decision", "decision", "ip prefix", "ip/prefix", "prefix", "company name", "address"}
COUNTRY_END_RE = re.compile(r"\b(?:US|USA|United States|CA|Canada)\.?\s*$", re.IGNORECASE)
STREET_HINT_RE = re.compile(
    r"\b(?:st|street|rd|road|ave|avenue|blvd|boulevard|dr|drive|hwy|highway|pkwy|parkway|plz|plaza|ln|lane|ct|court|cir|circle|way)\b",
    re.IGNORECASE,
)


def build_catalog(
    parent_company: str,
    subsidiaries_text: str,
    aliases_text: str,
    addresses_text: str,
    accepted_domains_text: str,
) -> CompanyCatalog:
    accepted_entities = []
    if parent_company.strip():
        accepted_entities.append(parent_company.strip())
    accepted_entities.extend(parse_company_lines(subsidiaries_text))
    deduped = []
    seen = set()
    for entity in accepted_entities:
        key = normalize_company_name(entity)
        if key and key not in seen:
            seen.add(key)
            deduped.append(entity)
    return CompanyCatalog(
        parent_company=parent_company.strip(),
        accepted_entities=deduped,
        aliases=parse_alias_lines(aliases_text),
        known_addresses=parse_address_evidence(addresses_text),
        accepted_domains=parse_domain_lines(accepted_domains_text),
    )


def dataframe_to_rows(df: pd.DataFrame) -> List[InputRow]:
    working = df.copy()
    working = working.iloc[:, :4]
    while working.shape[1] < 4:
        working[working.shape[1]] = ""
    working.columns = ["A", "B", "C", "D"]
    rows: List[InputRow] = []
    for index, row in enumerate(working.itertuples(index=False), start=1):
        values = [str(value).strip() if pd.notna(value) else "" for value in row]
        normalized_values = {normalize_company_name(value) for value in values if value}
        if index == 1 and len(normalized_values & HEADER_ALIASES) >= 2:
            continue
        rows.append(
            InputRow(
                row_number=index,
                analyst_decision=_normalize_analyst_decision(values[0]),
                prefix=values[1],
                raw_company_name=values[2],
                raw_address=values[3],
            )
        )
    return rows


def _normalize_analyst_decision(value: str) -> str:
    normalized = value.strip().upper()
    if normalized in {"1", "Y", "YES", "T", "TRUE"}:
        return "TRUE"
    if normalized in {"0", "N", "NO", "F", "FALSE"}:
        return "FALSE"
    return normalized


def _format_reason(base: str, source_url: str = "") -> str:
    if source_url:
        return f"{base} Source: {source_url}"
    return base


def _domain_matches_accepted(domain: str, accepted_domain: str) -> bool:
    domain = domain.strip().lower().strip(".")
    accepted_domain = accepted_domain.strip().lower().strip(".")
    return bool(
        domain
        and accepted_domain
        and (domain == accepted_domain or domain.endswith(f".{accepted_domain}"))
    )


def _matching_whois_domains(record_domains: Iterable[str], accepted_domains: Iterable[str]) -> List[str]:
    accepted = [domain.strip().lower().strip(".") for domain in accepted_domains if domain.strip()]
    matches = {
        domain.strip().lower().strip(".")
        for domain in record_domains
        if any(_domain_matches_accepted(domain, accepted_domain) for accepted_domain in accepted)
    }
    return sorted(matches)


def _best_whois_candidate(catalog: CompanyCatalog, record_values: Iterable[tuple[str, str]]) -> tuple[str, str, int, str]:
    best_name = ""
    best_kind = "none"
    best_score = 0
    best_source = ""
    for source, value in record_values:
        matched, kind, score = classify_company_match(value, catalog)
        if score > best_score:
            best_name, best_kind, best_score, best_source = matched, kind, score, source
        if kind == "exact" and score == 100:
            return matched, kind, score, source
    return best_name, best_kind, best_score, best_source


def _whois_address_location_match(row_address: str, whois_addresses: Iterable[str]) -> str:
    row_normalized = normalize_address(row_address)
    if not row_normalized:
        return ""

    def location_tokens(address: str) -> tuple[str, str, str]:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return "", "", ""
        country = tokens[-1]
        state = ""
        postal = ""
        search_tokens = tokens[:-1] if country == "us" else tokens
        for token in reversed(search_tokens):
            if not postal and token.isdigit() and len(token) >= 4:
                postal = token
            if not state and len(token) == 2 and token.isalpha():
                state = token
            if state and postal:
                break
        return state, postal, country

    row_state, row_postal, row_country = location_tokens(row_address)
    for whois_address in whois_addresses:
        whois_normalized = normalize_address(whois_address)
        if row_normalized == whois_normalized:
            return "exact"
        whois_state, whois_postal, whois_country = location_tokens(whois_address)
        if row_country and row_country == whois_country and row_state and row_state == whois_state:
            if row_postal and whois_postal and row_postal == whois_postal:
                return "postal"
            return "state_country"
    return ""


def _run_whois_match(prefix: str, catalog: CompanyCatalog, whois_client: WhoisLookupClient) -> WhoisMatchEvaluation:
    if not prefix.strip():
        return WhoisMatchEvaluation(error="No prefix was available for WHOIS.")
    record = whois_client.lookup(prefix)
    org_display = "; ".join(record.org_names)
    net_display = record.net_name
    matching_domains = _matching_whois_domains(record.domains, catalog.accepted_domains)
    domain_display = ", ".join(matching_domains)
    address_display = "; ".join(record.addresses)
    registry_display = record.registry
    if record.error:
        return WhoisMatchEvaluation(
            org_display=org_display,
            net_display=net_display,
            domain_display=domain_display,
            address_display=address_display,
            registry_display=registry_display,
            error=f"WHOIS lookup failed: {record.error}",
            domain_matched=bool(matching_domains),
        )
    candidates: List[tuple[str, str]] = [("orgname", name) for name in record.org_names]
    if record.net_name:
        candidates.append(("netname", record.net_name))
    for raw in [record.net_name, *record.org_names]:
        candidates.extend(("netname_stripped", candidate) for candidate in strip_netname_prefix(raw))
    seen_candidates: set[str] = set()
    deduped_candidates: List[tuple[str, str]] = []
    for source, candidate in candidates:
        key = candidate.strip().lower()
        if not key or key in seen_candidates:
            continue
        seen_candidates.add(key)
        deduped_candidates.append((source, candidate))
    matched_name, kind, score, source = _best_whois_candidate(catalog, deduped_candidates)
    domain_matched = bool(matching_domains)
    if kind == "exact":
        if source == "orgname":
            match_type = "whois_orgname_exact"
        else:
            match_type = "whois_netname_exact"
        if domain_matched:
            match_type = f"{match_type}_domain"
        return WhoisMatchEvaluation(
            matched_name=matched_name,
            match_type=match_type,
            match_score=score,
            org_display=org_display,
            net_display=net_display,
            domain_display=domain_display,
            address_display=address_display,
            registry_display=registry_display,
            domain_matched=domain_matched,
            name_kind=kind,
        )
    if domain_matched and score >= 97 and matched_name:
        return WhoisMatchEvaluation(
            matched_name=matched_name,
            match_type="whois_inexact_name_domain",
            match_score=score,
            org_display=org_display,
            net_display=net_display,
            domain_display=domain_display,
            address_display=address_display,
            registry_display=registry_display,
            domain_matched=True,
            name_kind=kind,
        )
    if domain_matched:
        return WhoisMatchEvaluation(
            match_type="whois_domain_exact",
            match_score=100,
            org_display=org_display,
            net_display=net_display,
            domain_display=domain_display,
            address_display=address_display,
            registry_display=registry_display,
            domain_matched=True,
            name_kind=kind,
        )
    if score >= 97 and matched_name:
        return WhoisMatchEvaluation(
            matched_name=matched_name,
            match_type="whois_close_not_exact",
            match_score=score,
            org_display=org_display,
            net_display=net_display,
            domain_display=domain_display,
            address_display=address_display,
            registry_display=registry_display,
            domain_matched=False,
            name_kind=kind,
        )
    return WhoisMatchEvaluation(
        match_type="no_match",
        match_score=score,
        org_display=org_display,
        net_display=net_display,
        domain_display=domain_display,
        address_display=address_display,
        registry_display=registry_display,
        domain_matched=False,
        name_kind=kind,
    )


def _company_candidate_fragments(raw_company: str) -> List[str]:
    fragments: List[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = clean_company_name(value)
        key = normalize_company_name(cleaned)
        if cleaned and key and key not in seen:
            seen.add(key)
            fragments.append(cleaned)

    add(raw_company)
    for fragment in re.split(r"[;\n,]+", raw_company):
        add(fragment)
    return fragments


def _best_row_company_match(raw_company: str, catalog: CompanyCatalog) -> tuple[str, str, int, str]:
    best_name = ""
    best_kind = "none"
    best_score = 0
    best_fragment = ""
    for fragment in _company_candidate_fragments(raw_company):
        matched, kind, score = classify_company_match(fragment, catalog)
        if kind == "exact" and score == 100:
            return matched, kind, score, fragment
        if score > best_score:
            best_name, best_kind, best_score, best_fragment = matched, kind, score, fragment
    return best_name, best_kind, best_score, best_fragment


def _address_candidates(raw_address: str) -> List[str]:
    candidates: List[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = value.strip(" ,;\n\t")
        key = normalize_address(cleaned)
        if cleaned and key and key not in seen:
            seen.add(key)
            candidates.append(cleaned)

    for line in re.split(r"[;\n]+", raw_address):
        current: List[str] = []
        for part in line.split(","):
            segment = part.strip()
            if not segment:
                continue
            current.append(segment)
            joined = " ".join(current).strip()
            if COUNTRY_END_RE.search(joined):
                add(joined)
                current = []
        if current:
            add(" ".join(current))
    return candidates


def _looks_like_specific_address(address: str) -> bool:
    normalized = normalize_address(address)
    return bool(re.search(r"\d", normalized) and STREET_HINT_RE.search(normalized))


def _related_search_names(row_fragment: str, matched_name: str, catalog: CompanyCatalog) -> List[str]:
    names: List[str] = []
    seen: set[str] = set()
    for candidate in [row_fragment, matched_name, catalog.parent_company]:
        key = normalize_company_name(candidate)
        if key and key not in seen:
            seen.add(key)
            names.append(candidate)
    return names


EXACT_WHOIS_TYPES = {
    "whois_orgname_exact",
    "whois_netname_exact",
    "whois_orgname_exact_domain",
    "whois_netname_exact_domain",
}
INEXACT_WHOIS_TYPES = {"whois_inexact_name_domain", "whois_close_not_exact"}
TO_REVIEW = "To Review"
# RDAP records can list several addresses (customer, provider, contacts). Cap how many we
# try to confirm per row so one row cannot burn through live-search credit.
MAX_ADDRESSES_PER_ROW = 3

_METHOD_LABELS = {
    "known_address": "known address list",
    "datacenter": "known data-center list",
    "cache": "previously verified address",
    "domain_crawl": "accepted-domain page",
    "live_search": "web page found by live search",
}


@dataclass
class AddressCheck:
    """Outcome of trying to confirm an address for a matched company."""

    found: bool = False
    method: str = ""
    address: str = ""
    source_url: str = ""
    owner: str = ""
    location_only_url: str = ""
    search_error: str = ""
    saw_private: bool = False
    # searched_ok: at least one live search ran and returned results to check.
    # search_failed: a live search could not run (bad key, rate limit, network error).
    searched_ok: bool = False
    search_failed: bool = False
    debug: str = ""


@dataclass
class RowDecision:
    verdict: str = "FALSE"
    reason: str = "FALSE — No connection found with the company or any of its subsidiaries."
    matched_company: str = ""
    confidence: str = "Medium"
    match_type: str = "no_match"
    match_score: int = 0
    source_url: str = ""
    review_reason: str = ""
    search_returned: str = "No qualifying evidence found."


def _confirm_address(
    matched_name: str,
    name_kind: str,
    search_names: List[str],
    addresses: List[str],
    catalog: CompanyCatalog,
    address_cache: Optional[AddressEvidenceCache],
    domain_client: Optional[DomainEvidenceClient],
    search_client: Optional[BraveSearchClient],
    report: Callable[[str], None],
) -> AddressCheck:
    """Try to confirm the address, cheapest source first. Only exact-address evidence counts."""
    check = AddressCheck()
    debug_parts: List[str] = []
    search_ready = search_client is not None and search_client.is_configured()
    for candidate in addresses[:MAX_ADDRESSES_PER_ROW]:
        if is_private_address(candidate):
            check.saw_private = True
            continue
        if not is_usable_address(candidate):
            continue
        known = find_address_match(candidate, catalog.known_addresses)
        if known:
            return AddressCheck(True, "known_address", candidate, known.source_url, known.canonical_name)
        if name_kind == "exact" and normalize_address(candidate) in KNOWN_DATA_CENTER_ADDRESSES:
            return AddressCheck(True, "datacenter", candidate, "", matched_name)
        cached = address_cache.get(candidate, catalog) if address_cache is not None else None
        # Older runs cached location-only (city/state) hits; those are no longer proof of an address.
        if cached and str(cached.get("evidence_type", "")) == "exact_address":
            return AddressCheck(
                True,
                "cache",
                candidate,
                str(cached.get("source_url", "")).strip(),
                str(cached.get("matched_accepted_entity", "")).strip() or matched_name,
            )
        if domain_client is not None and catalog.accepted_domains:
            crawl_url = domain_client.find_address_evidence(catalog.accepted_domains, candidate)
            if crawl_url:
                return AddressCheck(True, "domain_crawl", candidate, crawl_url, matched_name)
        if search_ready:
            report(f"live searching {matched_name} + {candidate}")
            url, mode, error, debug = search_client.find_address_evidence(  # type: ignore[union-attr]
                search_names[0],
                candidate,
                catalog.accepted_domains,
                related_company_names=search_names[1:],
            )
            if debug:
                debug_parts.append(debug)
            if url and mode == "exact_address":
                found = AddressCheck(True, "live_search", candidate, url, matched_name)
                found.debug = "\n".join(debug_parts)
                return found
            if url and not check.location_only_url:
                check.location_only_url = url
            if url or error == SEARCH_NOT_FOUND:
                check.searched_ok = True
            elif error:
                check.search_failed = True
            if error:
                check.search_error = error
    if not search_ready and not check.search_error:
        check.search_error = "Live search is not configured (no Brave API key)."
    check.debug = "\n".join(debug_parts)
    return check


def _same_company(left: str, right: str) -> bool:
    return normalize_company_name(left) == normalize_company_name(right)


def _decide_from_address(matched_name: str, name_kind: str, name_score: int, check: AddressCheck) -> RowDecision:
    """Rule table: name matched + exact address confirmed -> TRUE; otherwise To Review."""
    decision = RowDecision(matched_company=matched_name, match_score=100 if name_kind == "exact" else name_score)
    name_label = "Exact" if name_kind == "exact" else "Inexact"
    if check.found:
        owner = check.owner or matched_name
        label = _METHOD_LABELS.get(check.method, check.method)
        decision.verdict = "TRUE"
        decision.source_url = check.source_url
        decision.search_returned = f"Address confirmed via {label}: {check.address}."
        if not _same_company(owner, matched_name):
            decision.matched_company = owner
            decision.confidence = "Medium"
            decision.match_type = f"cross_entity_address_{check.method}"
            decision.reason = _format_reason(
                f"TRUE — Company name matched {matched_name}; address is verified for accepted company {owner} ({label}).",
                check.source_url,
            )
        elif name_kind == "exact":
            decision.confidence = "High"
            decision.match_type = f"exact_name_exact_address_{check.method}"
            decision.reason = _format_reason(f"TRUE — Exact company name + exact address match ({label}).", check.source_url)
        else:
            decision.confidence = "Medium"
            decision.match_type = f"inexact_name_exact_address_{check.method}"
            decision.reason = _format_reason(f"TRUE — Inexact company name + exact address match ({label}).", check.source_url)
        return decision

    # Unchanged rule: registry addresses marked "Private Address" cannot be searched, so an exact
    # name match is accepted on its own.
    if check.saw_private and name_kind == "exact":
        decision.verdict = "TRUE"
        decision.confidence = "High"
        decision.match_type = "private_address_exact_name"
        decision.reason = "TRUE — Exact company name + private address."
        decision.search_returned = "Address was classified as Private Address."
        return decision

    # Inexact name (missing/different legal ending, acronym, close spelling): the address decides.
    # The search ran and found no exact address -> FALSE. If the search could not run -> To Review.
    if name_kind != "exact" and check.searched_ok and not check.search_failed:
        decision.verdict = "FALSE"
        decision.confidence = "Medium"
        decision.match_type = "inexact_name_address_not_found"
        decision.reason = (
            f"FALSE — Company name is close to {matched_name} but not an exact accepted name, "
            "and live search did not find the exact address. Add the name to Accepted Subsidiaries "
            "or Alias / DBA if it should count."
        )
        decision.search_returned = "Live search ran but found no exact-address evidence."
        if check.location_only_url:
            decision.reason += f" Location-only evidence (same city/state, not counted): {check.location_only_url}"
        return decision

    decision.verdict = "FALSE"
    decision.confidence = TO_REVIEW
    decision.match_type = f"{name_kind}_name_address_unconfirmed"
    if name_kind == "exact":
        decision.review_reason = "Company name matched, but the address could not be confirmed."
        reason = (
            f"To Review — {name_label} company name matched {matched_name}, "
            "but the address could not be confirmed online. Verdict: FALSE."
        )
    else:
        decision.review_reason = "Company name is not exact and live search could not run to check the address."
        reason = (
            f"To Review — Company name is close to {matched_name} but not exact, and live search could not run "
            f"to check the address ({check.search_error or 'no search'}). Verdict: FALSE."
        )
    returned = "Address was not confirmed."
    if check.location_only_url:
        reason += f" Location-only evidence (same city/state, not counted): {check.location_only_url}"
        returned += f" Only location-level (city/state) evidence was found: {check.location_only_url}."
    elif check.search_error:
        returned += f" Diagnostic: {check.search_error}"
    decision.reason = reason
    decision.search_returned = returned
    return decision


def validate_standard_rows(
    rows: List[InputRow],
    catalog: CompanyCatalog,
    whois_client: WhoisLookupClient,
    domain_client: Optional[DomainEvidenceClient] = None,
    search_client: Optional[BraveSearchClient] = None,
    verify_whois_addresses: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    address_cache: Optional[AddressEvidenceCache] = None,
) -> List[ValidationResult]:
    """Validate rows with the name + address rule.

    1. Row has a company name and an address:
         name not accepted                     -> FALSE (no search is run)
         exact name, address found             -> TRUE High
         exact name, address not found         -> To Review (verdict FALSE)
         inexact name, address found           -> TRUE Medium
         inexact name, searched and not found  -> FALSE
         inexact name, search could not run    -> To Review
       "Inexact" = same name with a missing/different legal ending, an acronym, or a close spelling.
    2. Row is missing the name or the address: fill it in from RDAP, then apply the same rule.
    """
    results: List[ValidationResult] = []
    total_rows = len(rows)
    if address_cache is None:
        address_cache = AddressEvidenceCache()
    for index, row in enumerate(rows, start=1):
        if progress_callback is not None:
            progress_callback(index - 1, total_rows, f"Preparing row {row.row_number}")

        def report(message: str, _row_number: int = row.row_number, _index: int = index) -> None:
            if progress_callback is not None:
                progress_callback(_index - 1, total_rows, f"Row {_row_number}: {message}")

        matched_name, name_kind, name_score, matched_fragment = _best_row_company_match(row.raw_company_name, catalog)
        cleaned_company = matched_fragment or clean_company_name(row.raw_company_name)
        address_candidates = _address_candidates(row.raw_address)
        cleaned_address = "; ".join(address_candidates) if address_candidates else row.raw_address.strip()
        has_address = any(is_usable_address(a) or is_private_address(a) for a in address_candidates)
        has_name = bool(cleaned_company)

        whois_orgname = whois_netname = whois_domains = whois_addresses = whois_registry = ""
        live_search_debug = ""
        decision = RowDecision(match_score=name_score)

        if has_name and has_address:
            search_summary = (
                "Row had a company name and address: checked the name against accepted companies, then tried to "
                "confirm the address (known addresses, verified-address cache, accepted-domain crawl, live search). "
                "RDAP was not needed."
            )
            if not matched_name:
                decision.reason = "FALSE — Company name did not match the parent company or any accepted subsidiary."
                decision.search_returned = (
                    f"Best accepted-name similarity was {name_score}/100, below the match threshold. "
                    "No address search was run."
                )
            else:
                search_names = _related_search_names(matched_fragment, matched_name, catalog)
                check = _confirm_address(
                    matched_name, name_kind, search_names, address_candidates, catalog,
                    address_cache, domain_client, search_client, report,
                )
                live_search_debug = check.debug
                decision = _decide_from_address(matched_name, name_kind, name_score, check)
                if check.found and check.method in {"domain_crawl", "live_search"}:
                    address_cache.put(check.address, decision.matched_company, check.source_url, "exact_address", decision.confidence)
        elif row.prefix.strip():
            missing = "company name and address" if not has_name and not has_address else ("address" if not has_address else "company name")
            search_summary = f"Row was missing the {missing}, so RDAP was used to fill it in."
            report("RDAP lookup")
            evaluation = _run_whois_match(row.prefix, catalog, whois_client)
            whois_orgname = evaluation.org_display
            whois_netname = evaluation.net_display
            whois_domains = evaluation.domain_display
            whois_addresses = evaluation.address_display
            whois_registry = evaluation.registry_display
            if matched_name:
                use_name, use_kind, use_score = matched_name, name_kind, name_score
            elif evaluation.match_type in EXACT_WHOIS_TYPES:
                use_name, use_kind, use_score = evaluation.matched_name, "exact", evaluation.match_score
            elif evaluation.match_type in INEXACT_WHOIS_TYPES:
                use_name, use_kind, use_score = evaluation.matched_name, "inexact", evaluation.match_score
            else:
                use_name, use_kind, use_score = "", "none", evaluation.match_score

            if evaluation.error and not use_name:
                decision.verdict = "FALSE"
                decision.confidence = TO_REVIEW
                decision.match_type = "whois_error"
                decision.review_reason = "RDAP lookup failed."
                decision.reason = f"To Review — RDAP lookup failed, so the row could not be checked: {evaluation.error}. Verdict: FALSE."
                decision.search_returned = evaluation.error
            elif use_name:
                addresses = [a for a in address_candidates if is_usable_address(a) or is_private_address(a)]
                if not addresses:
                    addresses = _address_candidates(evaluation.address_display)
                search_names = _related_search_names(matched_fragment or use_name, use_name, catalog)
                check = _confirm_address(
                    use_name, use_kind, search_names, addresses, catalog,
                    address_cache, domain_client, search_client, report,
                )
                live_search_debug = check.debug
                decision = _decide_from_address(use_name, use_kind, use_score, check)
                decision.match_type = f"whois_{decision.match_type}" if not matched_name else decision.match_type
                if check.found and check.method in {"domain_crawl", "live_search"}:
                    address_cache.put(check.address, decision.matched_company, check.source_url, "exact_address", decision.confidence)
            elif evaluation.match_type == "whois_domain_exact":
                decision.confidence = TO_REVIEW
                decision.match_type = "whois_domain_exact"
                decision.match_score = evaluation.match_score
                decision.review_reason = "RDAP domain matched an accepted domain without an accepted company name."
                decision.reason = "To Review — RDAP domain matched an accepted domain, but the entity name was not an accepted company. Verdict: FALSE."
                decision.search_returned = f"RDAP exposed accepted domain(s): {whois_domains}."
            else:
                decision.reason = "FALSE — RDAP name did not match the parent company or any accepted subsidiary."
                decision.search_returned = "RDAP resolved the prefix, but no customer/org name or NetName matched an accepted company."
                decision.match_score = evaluation.match_score
        else:
            search_summary = "Row had no prefix and was missing the company name or address."
            decision.confidence = TO_REVIEW
            decision.match_type = "insufficient_data"
            decision.review_reason = "Row is missing data."
            decision.reason = "To Review — Row is missing the prefix and the company name or address. Verdict: FALSE."
            decision.search_returned = "Nothing to check."

        is_review = decision.confidence == TO_REVIEW
        mismatch = (
            row.analyst_decision in {"TRUE", "FALSE"}
            and row.analyst_decision != decision.verdict
            and not is_review
        )
        audit_steps = [
            f"1. Row number: {row.row_number}",
            f"2. Company name extracted: {cleaned_company or '[blank/unusable]'}",
            f"3. Address found in the row: {cleaned_address or '[blank]'}",
            f"4. What the engine searched: {search_summary}",
            f"5. What the search returned: {decision.search_returned}{f' Registry: {whois_registry}.' if whois_registry else ''}",
            f"6. Which subsidiary matched: {decision.matched_company or 'No accepted subsidiary matched.'}",
            f"7. Verdict: {decision.verdict}",
            f"8. Column F output: {decision.reason}",
            f"9. Column G output: {decision.matched_company or '[blank]'}",
            f"10. Column H output: {decision.confidence}",
        ]
        if whois_orgname or whois_netname or whois_domains or whois_addresses:
            audit_steps.append(
                "WHOIS Evidence: "
                f"OrgName={whois_orgname or '[blank]'}; "
                f"NetName={whois_netname or '[blank]'}; "
                f"Domains={whois_domains or '[blank]'}; "
                f"Addresses={whois_addresses or '[blank]'}"
            )
        if live_search_debug:
            audit_steps.append(f"Live Search Debug:\n{live_search_debug}")
        results.append(
            ValidationResult(
                row_number=row.row_number,
                column_a=row.analyst_decision,
                column_b=row.prefix,
                column_c=row.raw_company_name,
                column_d=row.raw_address,
                column_e=decision.verdict,
                column_f=decision.reason,
                column_g=decision.matched_company,
                column_h=decision.confidence,
                flag_mismatch=mismatch,
                cleaned_company_name=cleaned_company,
                cleaned_address=cleaned_address,
                matched_subsidiary=decision.matched_company,
                match_type=decision.match_type,
                match_score=decision.match_score,
                whois_orgname=whois_orgname,
                whois_netname=whois_netname,
                whois_domains=whois_domains,
                whois_addresses=whois_addresses,
                whois_registry=whois_registry,
                source_url=decision.source_url,
                review_reason=decision.review_reason,
                live_search_debug=live_search_debug,
                audit_steps=audit_steps,
            )
        )
        if progress_callback is not None:
            progress_callback(index, total_rows, f"Completed row {row.row_number}")
    return results


def validate_whois_only_prefixes(
    prefixes: List[str],
    catalog: CompanyCatalog,
    whois_client: WhoisLookupClient,
    search_client: Optional[BraveSearchClient] = None,
    verify_whois_addresses: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[WhoisOnlyResult]:
    results: List[WhoisOnlyResult] = []
    total_prefixes = len(prefixes)
    for index, prefix in enumerate(prefixes, start=1):
        if progress_callback is not None:
            progress_callback(index - 1, total_prefixes, f"Looking up {prefix}")
        whois_evaluation = _run_whois_match(prefix, catalog, whois_client)
        matched_name = whois_evaluation.matched_name
        match_type = whois_evaluation.match_type
        score = whois_evaluation.match_score
        org_names = whois_evaluation.org_display
        net_name = whois_evaluation.net_display
        whois_domains = whois_evaluation.domain_display
        whois_addresses = whois_evaluation.address_display
        registry_name = whois_evaluation.registry_display
        whois_error = whois_evaluation.error
        verdict = "FALSE"
        reason = "FALSE — WHOIS resolved the prefix, but no accepted company or subsidiary matched OrgName or NetName."
        confidence = "Medium"
        review_reason = ""
        if whois_error:
            reason = f"FALSE — {whois_error}"
        elif match_type in {"whois_orgname_exact", "whois_netname_exact", "whois_orgname_exact_domain", "whois_netname_exact_domain", "whois_inexact_name_domain"}:
            verdict = "TRUE"
            exact_whois_name = match_type.startswith(("whois_orgname_exact", "whois_netname_exact"))
            confidence = "High" if whois_evaluation.domain_matched or exact_whois_name else "Medium"
            reason = "TRUE — WHOIS/RDAP matched accepted company."
            if whois_evaluation.domain_matched:
                reason += f" Accepted domain evidence: {whois_evaluation.domain_display}."
            elif whois_addresses:
                reason += " WHOIS address was present for audit."
            if (
                verify_whois_addresses
                and not whois_evaluation.domain_matched
                and whois_addresses
                and search_client is not None
                and search_client.is_configured()
            ):
                candidate_address = whois_addresses.split("; ", 1)[0]
                live_search_url, _, live_search_error, _ = search_client.find_address_evidence(
                    matched_name,
                    candidate_address,
                    catalog.accepted_domains,
                    related_company_names=[catalog.parent_company],
                )
                if live_search_url:
                    confidence = "High"
                    match_type = f"{match_type}_address_verified"
                    reason += f" Web address corroboration found at {live_search_url}."
                elif live_search_error:
                    reason += f" Web address corroboration did not confirm it: {live_search_error}."
        elif match_type == "whois_close_not_exact":
            verdict = "FALSE"
            confidence = "To Review"
            review_reason = "WHOIS very close but not exact."
            reason = "To Review — WHOIS entity name was very close to accepted subsidiary but not exact. Verdict: FALSE."
        elif match_type == "whois_domain_exact":
            verdict = "FALSE"
            confidence = "To Review"
            review_reason = "WHOIS domain matched accepted domain without exact entity name."
            reason = "To Review — WHOIS domain matched an accepted domain, but the entity name was not exact. Verdict: FALSE."
        results.append(
            WhoisOnlyResult(
                input_prefix=prefix,
                whois_orgname=org_names,
                whois_netname=net_name,
                whois_domains=whois_domains,
                whois_addresses=whois_addresses,
                whois_registry=registry_name,
                matched_subsidiary=matched_name,
                match_type=match_type,
                match_score=score,
                verdict=verdict,
                reason=reason,
                confidence=confidence,
                review_reason=review_reason,
            )
        )
        if progress_callback is not None:
            progress_callback(index, total_prefixes, f"Completed {prefix}")
    return results
