"""Step 1: name + address decision rules.

Rule table (standard validator):
    name not accepted                       -> FALSE, no search
    name accepted + exact address confirmed -> TRUE (High exact name / Medium inexact name)
    name accepted + address not confirmed   -> To Review (verdict FALSE)
    city/state-only evidence                -> never counts as a confirmed address
    row missing name or address             -> fill in from RDAP, same rules
"""

from __future__ import annotations

import pandas as pd
import pytest

from address_evidence_cache import AddressEvidenceCache
from models import InputRow, WhoisRecord
from live_search import SEARCH_NOT_FOUND
from regression_fixture import ACCEPTED_SUBSIDIARIES, DBA_ALIASES, PARENT, ROWS, NoWhoisClient, ReplaySearchClient
from validator import build_catalog, dataframe_to_rows, validate_standard_rows

ADDRESS = "909 LOCUST ST DES MOINES IA 50309-2801 US"


class FakeSearch:
    def __init__(self, url=None, mode="", configured=True):
        self.url, self.mode, self.configured = url, mode, configured
        self.calls = []

    def is_configured(self):
        return self.configured

    def find_address_evidence(self, company_name, address, accepted_domains, related_company_names=()):
        self.calls.append((company_name, address))
        if self.url:
            return self.url, self.mode, "", f"fake {self.mode}"
        return None, "", SEARCH_NOT_FOUND, "fake miss"


class FakeWhois:
    def __init__(self, record: WhoisRecord):
        self.record = record
        self.calls = []

    def is_available(self):
        return True

    def lookup(self, prefix):
        self.calls.append(prefix)
        return self.record


@pytest.fixture
def cache(tmp_path):
    return AddressEvidenceCache(tmp_path)


@pytest.fixture
def accenture():
    return build_catalog(PARENT, ACCEPTED_SUBSIDIARIES, DBA_ALIASES, "", "")


def run(rows, catalog, cache, search=None, whois=None):
    return validate_standard_rows(
        rows, catalog, whois or NoWhoisClient(), domain_client=None, search_client=search, address_cache=cache
    )


def row(name="ACCENTURE LLP,", address=ADDRESS, prefix="206.136.82.208/29", analyst="TRUE", number=1):
    return InputRow(number, analyst, prefix, name, address)


# --- Rule table -------------------------------------------------------------------------------

def test_exact_name_and_exact_address_is_true_high(accenture, cache):
    [r] = run([row()], accenture, cache, FakeSearch("https://example.gov/vendor", "exact_address"))
    assert (r.column_e, r.column_h) == ("TRUE", "High")
    assert "https://example.gov/vendor" in r.column_f


def test_inexact_name_and_exact_address_is_true_medium(cache):
    catalog = build_catalog("Northwind Holdings", "Northwind Logistics Services Group", "", "", "")
    [r] = run([row(name="Northwind Logistic Services Group")], catalog, cache, FakeSearch("https://x.test/a", "exact_address"))
    assert (r.column_e, r.column_h) == ("TRUE", "Medium")


def test_exact_name_and_address_not_found_is_to_review_not_false(accenture, cache):
    [r] = run([row()], accenture, cache, FakeSearch())
    assert (r.column_e, r.column_h) == ("FALSE", "To Review")
    assert not r.flag_mismatch, "To Review must not be counted as an analyst mismatch"


def test_city_state_only_evidence_never_confirms_an_address(accenture, cache):
    [r] = run([row()], accenture, cache, FakeSearch("https://swaaae.org/Board-of-Directors", "state_country"))
    assert r.column_h == "To Review"
    assert "not counted" in r.column_f and "swaaae.org" in r.column_f


def test_unaccepted_name_is_false_and_runs_no_search(accenture, cache):
    search = FakeSearch("https://x.test/a", "exact_address")
    [r] = run([row(name="Acme Corp,", analyst="FALSE")], accenture, cache, search)
    assert (r.column_e, r.column_h) == ("FALSE", "Medium")
    assert search.calls == [], "no Brave credit should be spent on a row whose name does not match"


def test_without_brave_key_unconfirmed_rows_go_to_review(accenture, cache):
    [r] = run([row()], accenture, cache, FakeSearch(configured=False))
    assert r.column_h == "To Review"
    assert any("not configured" in step for step in r.audit_steps)


def test_private_address_with_exact_name_keeps_original_rule(accenture, cache):
    search = FakeSearch()
    [r] = run([row(address="Private Address")], accenture, cache, search)
    assert (r.column_e, r.column_h) == ("TRUE", "High")
    assert search.calls == []


# --- Caching ----------------------------------------------------------------------------------

def test_stale_location_only_cache_entry_is_ignored(accenture, cache):
    cache.put(ADDRESS, "Accenture", "https://www.indeed.com/viewjob", "state_country", "Medium")
    search = FakeSearch()
    [r] = run([row()], accenture, cache, search)
    assert r.column_h == "To Review"
    assert len(search.calls) == 1, "a stale city/state cache entry must not short-circuit the search"


def test_confirmed_address_is_cached_and_reused_without_a_second_search(accenture, cache):
    search = FakeSearch("https://example.gov/vendor", "exact_address")
    first, second = run([row(number=1), row(number=2)], accenture, cache, search)
    assert first.column_e == second.column_e == "TRUE"
    assert len(search.calls) == 1


def test_location_only_hits_are_not_cached(accenture, cache):
    run([row()], accenture, cache, FakeSearch("https://x.test/loc", "state_country"))
    assert cache.cache_stats()["entries"] == 0


# --- RDAP is only used when the row is missing data -------------------------------------------

def test_row_with_name_and_address_never_calls_rdap(accenture, cache):
    run([row()], accenture, cache, FakeSearch(), whois=NoWhoisClient())  # NoWhoisClient raises if called


def test_missing_address_uses_rdap_then_same_rule(accenture, cache):
    whois = FakeWhois(WhoisRecord(prefix="206.136.82.208/29", org_names=["ACCENTURE LLP"], addresses=[ADDRESS]))
    search = FakeSearch("https://example.gov/vendor", "exact_address")
    [r] = run([row(address="")], accenture, cache, search, whois=whois)
    assert whois.calls == ["206.136.82.208/29"]
    assert (r.column_e, r.column_h) == ("TRUE", "High")
    assert search.calls and search.calls[0][1].startswith("909 LOCUST")


def test_missing_address_rdap_name_not_accepted_is_false(accenture, cache):
    whois = FakeWhois(WhoisRecord(prefix="1.2.3.0/29", org_names=["Acme Corp"], addresses=[ADDRESS]))
    search = FakeSearch("https://x.test/a", "exact_address")
    [r] = run([row(name="", address="")], accenture, cache, search, whois=whois)
    assert (r.column_e, r.column_h) == ("FALSE", "Medium")
    assert search.calls == []


def test_rdap_failure_is_to_review_not_false(accenture, cache):
    whois = FakeWhois(WhoisRecord(prefix="1.2.3.0/29", error="timed out"))
    [r] = run([row(name="", address="")], accenture, cache, FakeSearch(), whois=whois)
    assert r.column_h == "To Review"
    assert "timed out" in r.column_f


# --- Regression: the 25 analyst-reviewed rows -------------------------------------------------

def test_regression_rows_have_no_hard_mismatches(accenture, cache):
    results = run(dataframe_to_rows(pd.DataFrame(ROWS)), accenture, cache, ReplaySearchClient())
    assert len(results) == 25
    assert [r.row_number for r in results if r.flag_mismatch] == []


def test_regression_rows_no_true_from_city_state_evidence(accenture, cache):
    results = run(dataframe_to_rows(pd.DataFrame(ROWS)), accenture, cache, ReplaySearchClient())
    for r in results:
        if r.column_e == "TRUE":
            assert "state_country" not in r.match_type, (r.row_number, r.match_type)
    junk = ("meetbeagle.com", "veripages.com", "swaaae.org", "allpages.com")
    assert not any(r.column_e == "TRUE" and any(j in r.source_url for j in junk) for r in results)


def test_regression_expected_verdicts(accenture, cache):
    results = {r.column_b: r for r in run(dataframe_to_rows(pd.DataFrame(ROWS)), accenture, cache, ReplaySearchClient())}
    # Exact-address evidence was found for these in the recorded runs.
    for prefix in ("65.203.39.184/29", "65.205.134.216/29", "65.216.182.0/28"):
        assert (results[prefix].column_e, results[prefix].column_h) == ("TRUE", "High"), prefix
    # The five rows the old engine wrongly marked FALSE are now To Review (Steps 3-4 aim to make them TRUE).
    for prefix in ("12.188.169.208/28", "152.193.173.184/30", "173.252.132.152/30", "206.136.82.208/29", "208.244.7.8/29"):
        assert results[prefix].column_h == "To Review", prefix
    # "Accenture US" is exact via the DBA list; its address was not found, so it is To Review (analyst said FALSE).
    assert results["208.185.177.200/29"].column_h == "To Review"
