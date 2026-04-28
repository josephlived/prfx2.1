from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Iterable, List, Optional, Tuple

from models import AddressEvidence, CompanyCatalog

try:
    from rapidfuzz import fuzz  # type: ignore
except ImportError:  # pragma: no cover
    fuzz = None


LEGAL_SUFFIXES = {
    "inc",
    "incorporated",
    "llc",
    "l.l.c",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "plc",
    "na",
    "n.a",
    "sa",
    "ag",
    "gmbh",
    "lp",
    "llp",
}

NOISE_PATTERNS = [
    r"for abuse issues.*",
    r"abuse@[\w.\-]+",
    r"\bhostmaster\b.*",
    r"\bmaintainer\b.*",
    r"\bmntner\b.*",
    r"\bmnt\b.*",
    r"\bas\d{1,10}-mnt\b.*",
    r"addresses within this block are non-portable\.?",
    r"\breg@.*",
    r"\b\d{1,2}:\d{2}:\d{2}\b.*",
    r"\bmon\b.*\bedt\b.*",
]

ADDRESS_REPLACEMENTS = {
    r"\bn\b": "north",
    r"\bs\b": "south",
    r"\be\b": "east",
    r"\bw\b": "west",
    r"\bne\b": "northeast",
    r"\bnw\b": "northwest",
    r"\bse\b": "southeast",
    r"\bsw\b": "southwest",
    r"\bst\b": "street",
    r"\brd\b": "road",
    r"\bblvd\b": "boulevard",
    r"\bave\b": "avenue",
    r"\bdr\b": "drive",
    r"\bcir\b": "circle",
    r"\bpkwy\b": "parkway",
    r"\bctr\b": "center",
    r"\bste\b": "suite",
    r"\bfl\b": "floor",
    r"\bi h\b": "ih",
    r"\bu\.s\.?\b": "us",
    r"\busa\b": "us",
    r"\bunited states\b": "us",
}

ARTICLES = {"the"}

COMPANY_ABBREVIATIONS = {
    "intl": "international",
    "intnl": "international",
    "svc": "services",
    "svcs": "services",
    "tech": "technology",
    "techs": "technologies",
    "mgmt": "management",
    "mfg": "manufacturing",
}


def parse_company_lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_alias_lines(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for splitter in ("=>", "->", "|", "="):
            if splitter in line:
                alias, canonical = [part.strip() for part in line.split(splitter, 1)]
                if alias and canonical:
                    aliases[normalize_company_name(alias)] = canonical
                break
    return aliases


def parse_address_evidence(text: str) -> List[AddressEvidence]:
    entries: List[AddressEvidence] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 2:
            continue
        source_url = parts[2] if len(parts) > 2 else ""
        entry = AddressEvidence(
            canonical_name=parts[0],
            address=parts[1],
            source_url=source_url,
        )
        entry.normalized_name = normalize_company_name(entry.canonical_name)
        entry.normalized_address = normalize_address(entry.address)
        entries.append(entry)
    return entries


def strip_netname_prefix(value: str) -> List[str]:
    cleaned = value.strip()
    if not cleaned:
        return []
    variants: List[str] = []
    seen = set()

    def add(candidate: str) -> None:
        candidate = candidate.strip(" -_")
        if candidate and candidate not in seen:
            seen.add(candidate)
            variants.append(candidate)

    without_net = re.sub(r"^net[-_]", "", cleaned, flags=re.IGNORECASE)
    add(without_net)
    once_stripped = re.sub(r"^[A-Za-z]{2}[-_]", "", without_net, count=1)
    add(once_stripped)
    twice_stripped = re.sub(r"^[A-Za-z]{2}[-_]", "", once_stripped, count=1)
    add(twice_stripped)
    return variants


def normalize_domain(value: str) -> str:
    lowered = value.strip().lower()
    lowered = re.sub(r"^https?://", "", lowered)
    lowered = lowered.split("/", 1)[0]
    lowered = lowered.split("@")[-1]
    return lowered.strip().strip(".")


def parse_domain_lines(text: str) -> List[str]:
    domains: List[str] = []
    seen = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        domain_part = line.split("|", 1)[0].strip()
        normalized = normalize_domain(domain_part)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
    return domains


def extract_last_chain_node(raw_value: str) -> str:
    if not raw_value:
        return ""
    cleaned = raw_value.replace("↳;", ";").replace("↳", ";")
    parts = [part.strip() for part in cleaned.split(";") if part.strip()]
    return parts[-1] if parts else raw_value.strip()


def clean_company_name(raw_value: str) -> str:
    node = extract_last_chain_node(raw_value)
    working = node
    for pattern in NOISE_PATTERNS:
        working = re.sub(pattern, "", working, flags=re.IGNORECASE).strip()
    comma_parts = [part.strip() for part in working.split(",") if part.strip()]
    if len(comma_parts) >= 2:
        second_norm = normalize_company_name(comma_parts[1])
        if second_norm in LEGAL_SUFFIXES:
            candidate = f"{comma_parts[0]}, {comma_parts[1]}"
            if candidate.strip():
                return candidate.strip()
    candidates = [part.strip() for part in re.split(r"[;,]", working) if part.strip()]
    for candidate in candidates:
        lower_candidate = candidate.lower()
        if any(token in lower_candidate for token in ("hostmaster", "abuse", "mnt", "maintainer", "@")):
            continue
        if re.fullmatch(r"as\d{1,10}-mnt", lower_candidate):
            continue
        if re.fullmatch(r"\d+", candidate):
            continue
        return candidate
    return ""


def normalize_company_name(value: str, remove_suffixes: bool = False, remove_articles: bool = False) -> str:
    lowered = value.lower().replace("&", " and ")
    lowered = re.sub(r"\bint['\u2019`]?l\b", "intl", lowered)
    lowered = re.sub(r"[^a-z0-9\s]", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    tokens = [COMPANY_ABBREVIATIONS.get(token, token) for token in lowered.split()]
    if remove_articles:
        tokens = [token for token in tokens if token not in ARTICLES]
    if remove_suffixes:
        tokens = [token for token in tokens if token not in LEGAL_SUFFIXES]
    return " ".join(tokens)


def normalize_address(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[^a-z0-9\s]", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    for pattern, replacement in ADDRESS_REPLACEMENTS.items():
        lowered = re.sub(pattern, replacement, lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def is_private_address(address: str) -> bool:
    return normalize_address(address).startswith("private address")


def is_usable_address(address: str) -> bool:
    return bool(address.strip()) and not is_private_address(address)


def company_acronym(name: str) -> str:
    tokens = normalize_company_name(name, remove_suffixes=True, remove_articles=True).split()
    if len(tokens) < 2:
        return ""
    return "".join(token[0] for token in tokens if token)


def fuzzy_score(left: str, right: str) -> int:
    if not left or not right:
        return 0
    if fuzz is not None:
        return int(fuzz.ratio(left, right))
    return int(round(SequenceMatcher(None, left, right).ratio() * 100))


def _strip_trailing_digits(value: str) -> str:
    return re.sub(r"\d+$", "", value).strip()


def classify_company_match(candidate: str, catalog: CompanyCatalog) -> Tuple[str, str, int]:
    cleaned = clean_company_name(candidate)
    normalized = normalize_company_name(cleaned)
    if not normalized:
        return "", "none", 0

    alias_hit = catalog.aliases.get(normalized)
    if alias_hit:
        return alias_hit, "exact", 100

    best_name = ""
    best_kind = "none"
    best_score = 0
    norm_no_suffix = normalize_company_name(cleaned, remove_suffixes=True, remove_articles=False)
    norm_no_suffix_article = normalize_company_name(cleaned, remove_suffixes=True, remove_articles=True)

    for entity in catalog.accepted_entities:
        entity_norm = normalize_company_name(entity)
        if normalized == entity_norm:
            return entity, "exact", 100
        if _strip_trailing_digits(normalized) == entity_norm:
            return entity, "exact", 100
        if normalized == company_acronym(entity):
            return entity, "exact", 100
        entity_no_suffix = normalize_company_name(entity, remove_suffixes=True, remove_articles=False)
        entity_no_suffix_article = normalize_company_name(entity, remove_suffixes=True, remove_articles=True)
        if norm_no_suffix and norm_no_suffix == entity_no_suffix:
            score = 99
            if score > best_score:
                best_name, best_kind, best_score = entity, "inexact", score
        if norm_no_suffix_article and norm_no_suffix_article == entity_no_suffix_article:
            return entity, "exact", 100
        score = fuzzy_score(normalized, entity_norm)
        if score > best_score:
            best_name, best_kind, best_score = entity, "inexact", score

    if best_score >= 97:
        return best_name, best_kind, best_score
    return "", "none", best_score


def find_address_match(address: str, evidence: Iterable[AddressEvidence]) -> Optional[AddressEvidence]:
    normalized_address = normalize_address(address)
    if not normalized_address:
        return None
    for entry in evidence:
        if normalized_address == entry.normalized_address:
            return entry
    return None


def coarse_location_match(address: str, evidence_entries: Iterable[AddressEvidence]) -> Optional[AddressEvidence]:
    normalized = normalize_address(address)
    if not normalized:
        return None
    tokens = normalized.split()
    if not tokens:
        return None
    country = tokens[-1]
    state = ""
    for token in reversed(tokens):
        if len(token) == 2 and token.isalpha():
            state = token
            break
    for entry in evidence_entries:
        entry_tokens = entry.normalized_address.split()
        if not entry_tokens:
            continue
        entry_country = entry_tokens[-1]
        if country != entry_country:
            continue
        if country == "us" and state:
            if f" {state} " in f" {entry.normalized_address} ":
                return entry
        elif country != "us":
            return entry
    return None
