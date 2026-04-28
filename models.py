from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AddressEvidence:
    canonical_name: str
    address: str
    source_url: str = ""
    normalized_name: str = ""
    normalized_address: str = ""


@dataclass
class CompanyCatalog:
    parent_company: str
    accepted_entities: List[str]
    aliases: dict[str, str]
    known_addresses: List[AddressEvidence]
    accepted_domains: List[str]


@dataclass
class InputRow:
    row_number: int
    analyst_decision: str
    prefix: str
    raw_company_name: str
    raw_address: str


@dataclass
class WhoisRecord:
    prefix: str
    org_names: List[str] = field(default_factory=list)
    net_name: str = ""
    domains: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    source_url: str = ""
    error: str = ""
    cached: bool = False
    registry: str = ""


@dataclass
class ValidationResult:
    row_number: int
    column_a: str
    column_b: str
    column_c: str
    column_d: str
    column_e: str
    column_f: str
    column_g: str
    column_h: str
    flag_mismatch: bool
    cleaned_company_name: str
    cleaned_address: str
    matched_subsidiary: str
    match_type: str
    match_score: int
    whois_orgname: str
    whois_netname: str
    whois_domains: str
    whois_addresses: str
    whois_registry: str
    source_url: str
    review_reason: str
    live_search_debug: str
    audit_steps: List[str] = field(default_factory=list)


@dataclass
class WhoisOnlyResult:
    input_prefix: str
    whois_orgname: str
    whois_netname: str
    whois_domains: str
    whois_addresses: str
    whois_registry: str
    matched_subsidiary: str
    match_type: str
    match_score: int
    verdict: str
    reason: str
    confidence: str
    review_reason: str = ""
