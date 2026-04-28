from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

import pandas as pd

from address_evidence_cache import AddressEvidenceCache
from matching import (
    classify_company_match,
    clean_company_name,
    coarse_location_match,
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
from live_search import BraveSearchClient
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


def validate_standard_rows(
    rows: List[InputRow],
    catalog: CompanyCatalog,
    whois_client: WhoisLookupClient,
    domain_client: Optional[DomainEvidenceClient] = None,
    search_client: Optional[BraveSearchClient] = None,
    verify_whois_addresses: bool = False,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    total_rows = len(rows)
    address_cache = AddressEvidenceCache()
    for index, row in enumerate(rows, start=1):
        if progress_callback is not None:
            progress_callback(index - 1, total_rows, f"Preparing row {row.row_number}")
        matched_name, name_kind, name_score, matched_fragment = _best_row_company_match(row.raw_company_name, catalog)
        cleaned_company = matched_fragment or clean_company_name(row.raw_company_name)
        address_candidates = _address_candidates(row.raw_address)
        cleaned_address = "; ".join(address_candidates) if address_candidates else row.raw_address.strip()
        usable_address_candidates = [address for address in address_candidates if is_usable_address(address)]
        normalized_address = normalize_address(address_candidates[0]) if address_candidates else normalize_address(cleaned_address)

        search_summary = "Checked accepted company candidates in the row, split row addresses, known address book, accepted-domain crawl, and live search. WHOIS is used only when row name or address evidence is missing."
        search_returned = "No qualifying evidence found."
        matched_subsidiary = ""
        column_e = "FALSE"
        column_f = "FALSE — No connection found with the company or any of its subsidiaries."
        column_g = ""
        column_h = "Medium"
        match_type = "no_match"
        match_score = name_score
        source_url = ""
        review_reason = ""
        whois_orgname = ""
        whois_netname = ""
        whois_domains = ""
        whois_addresses = ""
        whois_registry = ""
        domain_diagnostics: List[str] = []
        live_search_debug = ""
        whois_evaluation = WhoisMatchEvaluation()
        address_match = None
        location_match = None

        if matched_name and address_candidates:
            for candidate_address in address_candidates:
                candidate_normalized = normalize_address(candidate_address)
                candidate_address_match = find_address_match(candidate_address, catalog.known_addresses)
                company_specific_entries = [
                    entry for entry in catalog.known_addresses if entry.canonical_name == matched_name
                ]
                candidate_location_match = coarse_location_match(candidate_address, company_specific_entries) if company_specific_entries else None

                if candidate_address_match:
                    address_match = candidate_address_match
                    search_returned = f"Exact known address matched {candidate_address_match.canonical_name}: {candidate_address}."
                    matched_subsidiary = candidate_address_match.canonical_name
                    column_g = matched_subsidiary
                    source_url = candidate_address_match.source_url
                    if name_kind == "exact" and matched_name == matched_subsidiary:
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                        column_h = "High"
                        match_type = "direct_exact_name_exact_address"
                        match_score = 100
                    elif name_kind == "inexact" and matched_name == matched_subsidiary:
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                        column_h = "Medium"
                        match_type = "direct_inexact_name_exact_address"
                        match_score = name_score
                    else:
                        column_e = "TRUE"
                        column_f = _format_reason(
                            f"TRUE — Address matched accepted subsidiary {matched_subsidiary}.",
                            source_url,
                        )
                        column_h = "Medium"
                        match_type = "cross_subsidiary_address"
                        match_score = max(name_score, 100 if matched_subsidiary else 0)
                    break

                if is_private_address(candidate_address):
                    search_returned = f"Address was classified as Private Address: {candidate_address}."
                    if name_kind == "exact":
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = "TRUE — Exact company name + private address."
                        column_g = matched_name
                        column_h = "High"
                        match_type = "private_address_exact_name"
                        match_score = 100
                    elif matched_name:
                        matched_subsidiary = matched_name
                        column_e = "FALSE"
                        column_f = "FALSE — Inexact name + private address."
                        column_g = matched_name
                        column_h = "Medium"
                        match_type = "private_address_inexact_name"
                        match_score = name_score
                    break

                if candidate_normalized in KNOWN_DATA_CENTER_ADDRESSES and name_kind == "exact":
                    search_returned = f"Address matched the known data-center list: {candidate_address}."
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = "TRUE — Exact company name + known data center address."
                    column_g = matched_name
                    column_h = "High"
                    match_type = "datacenter_exact_name"
                    match_score = 100
                    break

                if is_usable_address(candidate_address) and candidate_location_match:
                    location_match = candidate_location_match
                    search_returned = f"Location-level evidence matched {candidate_location_match.canonical_name}: {candidate_address}."
                    matched_subsidiary = candidate_location_match.canonical_name
                    column_g = matched_subsidiary
                    source_url = candidate_location_match.source_url
                    if name_kind == "exact" and matched_name == matched_subsidiary:
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                        column_h = "Medium"
                        match_type = "exact_name_state_country_only"
                        match_score = 100
                    elif matched_name:
                        column_e = "FALSE"
                        column_f = "FALSE — Inexact name + state / country match only."
                        column_h = "Medium"
                        match_type = "inexact_name_state_country_only"
                        match_score = name_score
                    break

                cached_address = address_cache.get(candidate_address, catalog) if is_usable_address(candidate_address) else None
                if cached_address:
                    cached_owner = str(cached_address.get("matched_accepted_entity", "")).strip()
                    source_url = str(cached_address.get("source_url", "")).strip()
                    cached_confidence = str(cached_address.get("confidence", "Medium")).strip() or "Medium"
                    cached_evidence_type = str(cached_address.get("evidence_type", "exact_address")).strip() or "exact_address"
                    matched_subsidiary = cached_owner
                    column_e = "TRUE"
                    column_g = cached_owner
                    column_h = cached_confidence
                    if cached_owner == matched_name:
                        column_f = _format_reason("TRUE — Accepted company name + cached verified address match.", source_url)
                        match_type = f"cached_{cached_evidence_type}"
                    else:
                        column_f = _format_reason(
                            f"TRUE — Accepted company name matched {matched_name}; exact address was cached as verified for accepted entity {cached_owner}.",
                            source_url,
                        )
                        match_type = "cached_cross_accepted_entity_address"
                    match_score = 100 if name_kind == "exact" else name_score
                    search_returned = f"Address evidence cache matched {cached_owner}: {candidate_address}."
                    break

                if is_usable_address(candidate_address) and domain_client is not None and catalog.accepted_domains:
                    if not domain_diagnostics:
                        domain_diagnostics = domain_client.diagnose_domains(catalog.accepted_domains[:5])
                    crawl_url = domain_client.find_address_evidence(catalog.accepted_domains, candidate_address)
                    if crawl_url:
                        search_returned = f"Exact address was found on accepted domain evidence page {crawl_url}: {candidate_address}."
                        source_url = crawl_url
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Accepted company name + exact address match.", source_url)
                        column_g = matched_name
                        column_h = "High" if name_kind == "exact" else "Medium"
                        match_type = "domain_exact_name_exact_address" if name_kind == "exact" else "domain_inexact_name_exact_address"
                        match_score = 100 if name_kind == "exact" else name_score
                        address_cache.put(candidate_address, matched_name, source_url, "exact_address", column_h)
                        break
                    if domain_diagnostics:
                        search_returned = f"Accepted-domain crawl could not confirm the address. Diagnostic: {domain_diagnostics[0]}"

                if search_client is not None and search_client.is_configured() and is_usable_address(candidate_address):
                    if progress_callback is not None:
                        progress_callback(index - 1, total_rows, f"Row {row.row_number}: live searching {matched_name} + {candidate_address}")
                    search_names = _related_search_names(matched_fragment, matched_name, catalog)
                    live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                        search_names[0],
                        candidate_address,
                        catalog.accepted_domains,
                        related_company_names=search_names[1:],
                    )
                    if live_search_url:
                        evidence_label = "exact address" if live_search_mode == "exact_address" else "location"
                        search_returned = f"Live search found {evidence_label} evidence at {live_search_url}: {candidate_address}."
                        source_url = live_search_url
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason(
                            "TRUE — Accepted company name + web-verified address match.",
                            source_url,
                        )
                        column_g = matched_name
                        column_h = "High" if live_search_mode == "exact_address" else "Medium"
                        match_type = "search_exact_name_exact_address" if live_search_mode == "exact_address" else "search_exact_name_state_country"
                        match_score = 100 if name_kind == "exact" else name_score
                        address_cache.put(candidate_address, matched_name, source_url, live_search_mode, column_h)
                        break
                    if live_search_error:
                        search_returned = f"Live search could not confirm {candidate_address}. Diagnostic: {live_search_error}"

                    if False and _looks_like_specific_address(candidate_address):
                        for accepted_entity in catalog.accepted_entities:
                            if accepted_entity == matched_name:
                                continue
                            if progress_callback is not None:
                                progress_callback(index - 1, total_rows, f"Row {row.row_number}: checking whether address belongs to {accepted_entity}")
                            cross_url, cross_mode, cross_error, live_search_debug = search_client.find_address_evidence(
                                accepted_entity,
                                candidate_address,
                                catalog.accepted_domains,
                                related_company_names=[catalog.parent_company],
                            )
                            if cross_url:
                                source_url = cross_url
                                matched_subsidiary = accepted_entity
                                column_e = "TRUE"
                                column_f = _format_reason(
                                    f"TRUE — Accepted company name matched {matched_name}; exact address matched another accepted entity {accepted_entity}.",
                                    source_url,
                                )
                                column_g = accepted_entity
                                column_h = "High" if cross_mode == "exact_address" else "Medium"
                                match_type = "cross_accepted_entity_address"
                                match_score = 100 if name_kind == "exact" else name_score
                                search_returned = f"Live search matched supplied address to accepted entity {accepted_entity}: {candidate_address}."
                                address_cache.put(candidate_address, accepted_entity, source_url, cross_mode, column_h)
                                break
                            if cross_error:
                                search_returned = f"Live search could not confirm {candidate_address}. Diagnostic: {cross_error}"
                        if column_e == "TRUE":
                            break

        if False:
            matched_subsidiary = whois_evaluation.matched_name
            column_e = "TRUE"
            column_g = matched_subsidiary
            match_type = whois_evaluation.match_type
            match_score = whois_evaluation.match_score
            search_summary = "WHOIS/RDAP-first validation using most-specific customer/org names, NetName, accepted domains, and WHOIS address fields."
            search_returned = f"WHOIS matched accepted company {matched_subsidiary}."
            address_location = _whois_address_location_match(cleaned_address, whois_evaluation.address_display.split("; "))
            exact_whois_name = whois_evaluation.match_type.startswith(("whois_orgname_exact", "whois_netname_exact"))
            reason_bits = [f"TRUE — WHOIS/RDAP name matched accepted company {matched_subsidiary}."]
            if whois_evaluation.domain_matched:
                reason_bits.append(f"Accepted domain evidence: {whois_evaluation.domain_display}.")
                column_h = "High"
            elif address_location:
                reason_bits.append(f"WHOIS address matched row address at {address_location.replace('_', ' ')} level.")
                column_h = "High"
            elif whois_evaluation.address_display:
                reason_bits.append("WHOIS address was present for audit.")
                column_h = "High" if exact_whois_name else "Medium"
            else:
                column_h = "High" if exact_whois_name else "Medium"

            if (
                verify_whois_addresses
                and not whois_evaluation.domain_matched
                and whois_evaluation.address_display
                and search_client is not None
                and search_client.is_configured()
            ):
                candidate_address = whois_evaluation.address_display.split("; ", 1)[0]
                live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                    matched_subsidiary,
                    candidate_address,
                    catalog.accepted_domains,
                    related_company_names=[catalog.parent_company],
                )
                if live_search_url:
                    source_url = live_search_url
                    reason_bits.append(f"Web address corroboration found at {source_url}.")
                    search_returned = f"WHOIS matched accepted company and live search corroborated address at {source_url}."
                    column_h = "High"
                    match_type = f"{match_type}_address_verified"
                elif live_search_error:
                    search_returned = f"WHOIS matched accepted company; web address corroboration did not confirm it. Diagnostic: {live_search_error}"
            column_f = " ".join(reason_bits)

        if column_e == "TRUE" or (matched_name and address_candidates):
            pass
        elif address_match:
            search_returned = f"Exact known address matched {address_match.canonical_name}."
            matched_subsidiary = address_match.canonical_name
            column_g = matched_subsidiary
            source_url = address_match.source_url
            if name_kind == "exact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                column_h = "High"
                match_type = "direct_exact_name_exact_address"
                match_score = 100
            elif name_kind == "inexact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                column_h = "Medium"
                match_type = "direct_inexact_name_exact_address"
                match_score = name_score
            else:
                column_e = "TRUE"
                column_f = _format_reason(
                    f"TRUE — Address matched accepted subsidiary {matched_subsidiary}.",
                    source_url,
                )
                column_h = "Medium"
                match_type = "cross_subsidiary_address"
                match_score = max(name_score, 100 if matched_subsidiary else 0)
        elif is_private_address(cleaned_address):
            search_returned = "Address was classified as Private Address."
            if name_kind == "exact":
                matched_subsidiary = matched_name
                column_e = "TRUE"
                column_f = "TRUE — Exact company name + private address."
                column_g = matched_name
                column_h = "High"
                match_type = "private_address_exact_name"
                match_score = 100
            elif matched_name:
                matched_subsidiary = matched_name
                column_e = "FALSE"
                column_f = "FALSE — Inexact name + private address."
                column_g = matched_name
                column_h = "Medium"
                match_type = "private_address_inexact_name"
                match_score = name_score
        elif normalized_address in KNOWN_DATA_CENTER_ADDRESSES and name_kind == "exact":
            search_returned = "Address matched the known data-center list."
            matched_subsidiary = matched_name
            column_e = "TRUE"
            column_f = "TRUE — Exact company name + known data center address."
            column_g = matched_name
            column_h = "High"
            match_type = "datacenter_exact_name"
            match_score = 100
        elif is_usable_address(cleaned_address) and location_match:
            search_returned = f"Location-level evidence matched {location_match.canonical_name}."
            matched_subsidiary = location_match.canonical_name
            column_g = matched_subsidiary
            source_url = location_match.source_url
            if name_kind == "exact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                column_h = "Medium"
                match_type = "exact_name_state_country_only"
                match_score = 100
            elif matched_name:
                column_e = "FALSE"
                column_f = "FALSE — Inexact name + state / country match only."
                column_h = "Medium"
                match_type = "inexact_name_state_country_only"
                match_score = name_score
        elif is_usable_address(cleaned_address) and domain_client is not None and catalog.accepted_domains:
            domain_diagnostics = domain_client.diagnose_domains(catalog.accepted_domains[:5])
            crawl_url = domain_client.find_address_evidence(catalog.accepted_domains, cleaned_address)
            if crawl_url:
                search_returned = f"Exact address was found on accepted domain evidence page {crawl_url}."
                source_url = crawl_url
                if name_kind == "exact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                    column_g = matched_name
                    column_h = "High"
                    match_type = "domain_exact_name_exact_address"
                    match_score = 100
                elif name_kind == "inexact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                    column_g = matched_name
                    column_h = "Medium"
                    match_type = "domain_inexact_name_exact_address"
                    match_score = name_score
                else:
                    column_e = "FALSE"
                    column_f = _format_reason(
                        "To Review — Exact address was found on an accepted domain, but the company name did not match an accepted entity. Verdict: FALSE.",
                        source_url,
                    )
                    column_h = "To Review"
                    match_type = "domain_address_name_unmatched"
                    review_reason = "Accepted-domain address evidence exists without accepted company-name match."
                    match_score = 100
            else:
                if domain_diagnostics:
                    search_returned = f"Accepted-domain crawl could not confirm the address. Diagnostic: {domain_diagnostics[0]}"
                if search_client is not None and search_client.is_configured() and cleaned_company and is_usable_address(cleaned_address):
                    live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                        cleaned_company or matched_name,
                        cleaned_address,
                        catalog.accepted_domains,
                        related_company_names=[matched_name, catalog.parent_company],
                    )
                    if live_search_url:
                        evidence_label = "exact address" if live_search_mode == "exact_address" else "location"
                        search_returned = f"Live search found {evidence_label} evidence at {live_search_url}."
                        source_url = live_search_url
                        if live_search_mode == "exact_address":
                            if name_kind == "exact" and matched_name:
                                matched_subsidiary = matched_name
                                column_e = "TRUE"
                                column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                                column_g = matched_name
                                column_h = "High"
                                match_type = "search_exact_name_exact_address"
                                match_score = 100
                            elif name_kind == "inexact" and matched_name:
                                matched_subsidiary = matched_name
                                column_e = "TRUE"
                                column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                                column_g = matched_name
                                column_h = "Medium"
                                match_type = "search_inexact_name_exact_address"
                                match_score = name_score
                            else:
                                column_e = "FALSE"
                                column_f = _format_reason(
                                    "To Review — Live search found exact address evidence, but the company name did not match an accepted entity. Verdict: FALSE.",
                                    source_url,
                                )
                                column_h = "To Review"
                                match_type = "search_address_name_unmatched"
                                review_reason = "Live-search address evidence exists without accepted company-name match."
                                match_score = 100
                        elif live_search_mode == "state_country" and name_kind == "exact" and matched_name:
                            matched_subsidiary = matched_name
                            column_e = "TRUE"
                            column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                            column_g = matched_name
                            column_h = "Medium"
                            match_type = "search_exact_name_state_country"
                            match_score = 100
                    elif live_search_error:
                        search_returned = f"Live search could not confirm the address. Diagnostic: {live_search_error}"
        elif cleaned_company and is_usable_address(cleaned_address) and search_client is not None and search_client.is_configured():
            live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                cleaned_company or matched_name,
                cleaned_address,
                catalog.accepted_domains,
                related_company_names=[matched_name, catalog.parent_company],
            )
            if live_search_url:
                evidence_label = "exact address" if live_search_mode == "exact_address" else "location"
                search_returned = f"Live search found {evidence_label} evidence at {live_search_url}."
                source_url = live_search_url
                if live_search_mode == "exact_address":
                    if name_kind == "exact" and matched_name:
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                        column_g = matched_name
                        column_h = "High"
                        match_type = "search_exact_name_exact_address"
                        match_score = 100
                    elif name_kind == "inexact" and matched_name:
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                        column_g = matched_name
                        column_h = "Medium"
                        match_type = "search_inexact_name_exact_address"
                        match_score = name_score
                    else:
                        column_e = "FALSE"
                        column_f = _format_reason(
                            "To Review — Live search found exact address evidence, but the company name did not match an accepted entity. Verdict: FALSE.",
                            source_url,
                        )
                        column_h = "To Review"
                        match_type = "search_address_name_unmatched"
                        review_reason = "Live-search address evidence exists without accepted company-name match."
                        match_score = 100
                elif live_search_mode == "state_country" and name_kind == "exact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                    column_g = matched_name
                    column_h = "Medium"
                    match_type = "search_exact_name_state_country"
                    match_score = 100
            elif live_search_error:
                search_returned = f"Live search could not confirm the address. Diagnostic: {live_search_error}"
        elif row.prefix.strip() and (not matched_name or not usable_address_candidates):
            whois_evaluation = _run_whois_match(row.prefix, catalog, whois_client)
            whois_orgname = whois_evaluation.org_display
            whois_netname = whois_evaluation.net_display
            whois_domains = whois_evaluation.domain_display
            whois_addresses = whois_evaluation.address_display
            whois_registry = whois_evaluation.registry_display
            whois_name = whois_evaluation.matched_name
            whois_type = whois_evaluation.match_type
            whois_score = whois_evaluation.match_score
            whois_error = whois_evaluation.error
            search_summary = "WHOIS/RDAP fallback because the row was missing an accepted company candidate or a usable address."
            if whois_error:
                search_returned = whois_error
                column_e = "FALSE"
                column_f = "FALSE — No connection found with the company or any of its subsidiaries."
                match_type = "no_match"
            elif whois_type in {"whois_orgname_exact", "whois_netname_exact", "whois_orgname_exact_domain", "whois_netname_exact_domain", "whois_inexact_name_domain"}:
                matched_subsidiary = whois_name
                column_e = "TRUE"
                column_g = whois_name
                exact_whois_name = whois_type.startswith(("whois_orgname_exact", "whois_netname_exact"))
                column_h = "High" if whois_evaluation.domain_matched or exact_whois_name else "Medium"
                column_f = "TRUE — WHOIS/RDAP matched accepted company."
                if whois_evaluation.domain_matched:
                    column_f += f" Accepted domain evidence: {whois_evaluation.domain_display}."
                match_type = whois_type
                match_score = whois_score
                search_returned = f"WHOIS matched accepted subsidiary {whois_name}."
                if whois_evaluation.address_display and search_client is not None and search_client.is_configured():
                    address_corroborated = False
                    for candidate_address in _address_candidates(whois_evaluation.address_display):
                        if progress_callback is not None:
                            progress_callback(index - 1, total_rows, f"Row {row.row_number}: verifying WHOIS address {candidate_address}")
                        live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                            matched_subsidiary,
                            candidate_address,
                            catalog.accepted_domains,
                            related_company_names=[catalog.parent_company],
                        )
                        if live_search_url:
                            address_corroborated = True
                            source_url = live_search_url
                            column_h = "High"
                            column_f += f" Web address corroboration found at {source_url}."
                            search_returned = f"WHOIS matched accepted company and live search corroborated {candidate_address} at {source_url}."
                            match_type = f"{match_type}_address_verified"
                            address_cache.put(candidate_address, matched_subsidiary, source_url, live_search_mode or "exact_address", column_h)
                            break
                        if live_search_error:
                            search_returned = f"WHOIS matched accepted company; web address corroboration did not confirm {candidate_address}. Diagnostic: {live_search_error}"
                    if not address_corroborated:
                        column_e = "FALSE"
                        column_h = "To Review"
                        review_reason = "WHOIS matched accepted company, but WHOIS address was not web-corroborated."
                        column_f = "To Review — WHOIS/RDAP matched an accepted company, but the WHOIS address could not be web-corroborated. Verdict: FALSE."
                        match_type = f"{whois_type}_address_unverified"
            elif whois_type == "whois_close_not_exact":
                matched_subsidiary = whois_name
                column_e = "FALSE"
                column_f = "To Review — WHOIS entity name was very close to accepted subsidiary but not exact. Verdict: FALSE."
                column_g = whois_name
                column_h = "To Review"
                match_type = whois_type
                match_score = whois_score
                review_reason = "WHOIS very close but not exact."
                search_returned = f"WHOIS was very close to accepted subsidiary {whois_name}, but not exact."
            elif whois_type == "whois_domain_exact":
                column_e = "FALSE"
                column_f = "To Review — WHOIS domain matched an accepted domain, but the entity name was not exact. Verdict: FALSE."
                column_h = "To Review"
                match_type = whois_type
                match_score = whois_score
                review_reason = "WHOIS domain matched accepted domain without exact entity name."
                search_returned = f"WHOIS exposed accepted domain(s): {whois_domains}."
            else:
                search_returned = "WHOIS resolved the prefix, but OrgName and NetName did not match an accepted company."
        elif not is_usable_address(cleaned_address):
            search_returned = "Address was blank or not usable."

        if column_e == "FALSE" and match_type == "no_match" and whois_evaluation.match_type == "whois_domain_exact":
            column_f = "To Review — WHOIS/RDAP exposed an accepted domain, but the entity name was not an accepted company. Verdict: FALSE."
            column_h = "To Review"
            match_type = whois_evaluation.match_type
            match_score = whois_evaluation.match_score
            review_reason = "WHOIS domain matched accepted domain without exact entity name."
            search_returned = f"WHOIS exposed accepted domain(s): {whois_evaluation.domain_display}."
        elif column_e == "FALSE" and match_type == "no_match" and whois_evaluation.match_type == "whois_close_not_exact":
            matched_subsidiary = whois_evaluation.matched_name
            column_f = "To Review — WHOIS/RDAP entity name was very close to an accepted company but not exact. Verdict: FALSE."
            column_g = matched_subsidiary
            column_h = "To Review"
            match_type = whois_evaluation.match_type
            match_score = whois_evaluation.match_score
            review_reason = "WHOIS very close but not exact."
            search_returned = f"WHOIS was very close to accepted company {matched_subsidiary}, but not exact."

        mismatch = row.analyst_decision in {"TRUE", "FALSE"} and row.analyst_decision != column_e
        audit_steps = [
            f"1. Row number: {row.row_number}",
            f"2. Company name extracted: {cleaned_company or '[blank/unusable]'}",
            f"3. Address found in the row: {cleaned_address or '[blank]'}",
            f"4. What the engine searched: {search_summary}",
            f"5. What the search returned: {search_returned}{f' Registry: {whois_registry}.' if whois_registry else ''}",
            f"6. Which subsidiary matched: {matched_subsidiary or 'No accepted subsidiary matched.'}",
            f"7. Verdict: {column_e}",
            f"8. Column F output: {column_f}",
            f"9. Column G output: {column_g or '[blank]'}",
            f"10. Column H output: {column_h}",
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
                column_e=column_e,
                column_f=column_f,
                column_g=column_g,
                column_h=column_h,
                flag_mismatch=mismatch,
                cleaned_company_name=cleaned_company,
                cleaned_address=cleaned_address,
                matched_subsidiary=matched_subsidiary,
                match_type=match_type,
                match_score=match_score,
                whois_orgname=whois_orgname,
                whois_netname=whois_netname,
                whois_domains=whois_domains,
                whois_addresses=whois_addresses,
                whois_registry=whois_registry,
                source_url=source_url,
                review_reason=review_reason,
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
