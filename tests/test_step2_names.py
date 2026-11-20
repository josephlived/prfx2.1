"""Step 2: name safety.

exact   = listed in Accepted Subsidiaries / Parent with the same legal ending (spelling variants of an
          ending are the same, e.g. L.L.P. == LLP), or listed in Alias / DBA.
inexact = same name with a missing/different legal ending, an acronym, or a very close spelling.

inexact + exact address found          -> TRUE Medium
inexact + live search ran, not found   -> FALSE
inexact + live search could not run    -> To Review
"""

from __future__ import annotations

import pandas as pd
import pytest

from address_evidence_cache import AddressEvidenceCache
from live_search import SEARCH_NOT_FOUND, BraveSearchClient
from matching import classify_company_match
from models import InputRow
from regression_fixture import ACCEPTED_SUBSIDIARIES, PARENT, ROWS, NoWhoisClient, ReplaySearchClient
from validator import build_catalog, dataframe_to_rows, validate_standard_rows

ADDRESS = "7777 BONHOMME AVE CLAYTON MO 63105-1911 US"


@pytest.fixture
def catalog():
    return build_catalog(
        "Accenture Plc",
        "Accenture LLP\nFirst Data\nHome Depot Inc\nAmerican Bankers Insurance Company",
        "Accenture US => Accenture Plc",
        "",
        "",
    )


@pytest.mark.parametrize(
    "name, expected_name, expected_kind",
    [
        ("ACCENTURE PLC", "Accenture Plc", "exact"),
        ("ACCENTURE LLP", "Accenture LLP", "exact"),
        ("ACCENTURE L.L.P.", "Accenture LLP", "exact"),  # dotted spelling of the same ending
        ("Accenture US", "Accenture Plc", "exact"),  # listed in Alias / DBA
        ("The Home Depot, Inc.", "Home Depot Inc", "exact"),
        ("Home Depot Incorporated", "Home Depot Inc", "exact"),  # Incorporated == Inc
        ("American Bankers Insurance Co", "American Bankers Insurance Company", "exact"),  # Co == Company
        ("Accenture", "Accenture Plc", "inexact"),  # legal ending missing
        ("Accenture Inc", "Accenture Plc", "inexact"),  # different legal ending
        ("FD", "First Data", "inexact"),  # acronyms are never exact
        ("ABI", "American Bankers Insurance Company", "inexact"),
        ("Accenture Consulting LLP", "", "none"),
        ("Acme Corp", "", "none"),
    ],
)
def test_name_classification(catalog, name, expected_name, expected_kind):
    matched, kind, _ = classify_company_match(name, catalog)
    assert (matched, kind) == (expected_name, expected_kind)


def test_bare_name_is_exact_only_when_listed_in_dba():
    without = build_catalog("Accenture Plc", "", "", "", "")
    with_dba = build_catalog("Accenture Plc", "", "Accenture => Accenture Plc", "", "")
    assert classify_company_match("ACCENTURE", without)[1] == "inexact"
    assert classify_company_match("ACCENTURE", with_dba)[1] == "exact"


class FakeSearch:
    def __init__(self, url=None, mode="", error=SEARCH_NOT_FOUND, configured=True):
        self.url, self.mode, self.error, self.configured = url, mode, error, configured
        self.calls = []

    def is_configured(self):
        return self.configured

    def find_address_evidence(self, company_name, address, accepted_domains, related_company_names=()):
        self.calls.append((company_name, address))
        if self.url:
            return self.url, self.mode, "", "fake hit"
        return None, "", self.error, "fake miss"


def run_one(name, search, tmp_path, catalog):
    row = InputRow(1, "TRUE", "208.244.7.8/29", name, ADDRESS)
    [result] = validate_standard_rows(
        [row], catalog, NoWhoisClient(), search_client=search, address_cache=AddressEvidenceCache(tmp_path)
    )
    return result


def test_inexact_name_exact_address_found_is_true_medium(catalog, tmp_path):
    r = run_one("ACCENTURE", FakeSearch("https://x.test/a", "exact_address"), tmp_path, catalog)
    assert (r.column_e, r.column_h) == ("TRUE", "Medium")


def test_inexact_name_searched_not_found_is_false(catalog, tmp_path):
    search = FakeSearch()
    r = run_one("ACCENTURE", search, tmp_path, catalog)
    assert (r.column_e, r.column_h) == ("FALSE", "Medium")
    assert search.calls, "the address must actually be searched before answering FALSE"
    assert "Alias / DBA" in r.column_f


def test_inexact_name_location_only_is_false(catalog, tmp_path):
    r = run_one("ACCENTURE", FakeSearch("https://x.test/city", "state_country"), tmp_path, catalog)
    assert (r.column_e, r.column_h) == ("FALSE", "Medium")
    assert "not counted" in r.column_f


@pytest.mark.parametrize(
    "search",
    [FakeSearch(configured=False), FakeSearch(error="HTTP Error 429: Too Many Requests")],
    ids=["no-brave-key", "rate-limited"],
)
def test_inexact_name_search_could_not_run_is_to_review(catalog, tmp_path, search):
    r = run_one("ACCENTURE", search, tmp_path, catalog)
    assert (r.column_e, r.column_h) == ("FALSE", "To Review")


def test_exact_name_not_found_is_still_to_review(catalog, tmp_path):
    r = run_one("ACCENTURE LLP", FakeSearch(), tmp_path, catalog)
    assert r.column_h == "To Review"


def test_acronym_needs_an_address_to_be_true(catalog, tmp_path):
    assert run_one("FD", FakeSearch(), tmp_path, catalog).column_e == "FALSE"
    assert run_one("FD", FakeSearch("https://x.test/a", "exact_address"), tmp_path / "b", catalog).column_h == "Medium"


# --- Live search must tell "searched, nothing found" apart from "could not search" --------------

def _client(tmp_path, search_result):
    client = BraveSearchClient("test-key", cache_dir=tmp_path)
    client._search = lambda query: search_result
    client._fetch_page = lambda url: ("", "blocked")
    return client


def test_live_search_reports_not_found_when_queries_ran(tmp_path):
    _, _, error, _ = _client(tmp_path, ([], "")).find_address_evidence("Accenture LLP", ADDRESS, [])
    assert error == SEARCH_NOT_FOUND


def test_live_search_reports_failure_when_no_query_ran(tmp_path):
    _, _, error, _ = _client(tmp_path, ([], "HTTP Error 401: Unauthorized")).find_address_evidence("Accenture LLP", ADDRESS, [])
    assert error == "HTTP Error 401: Unauthorized"


# --- Regression rows without a DBA list: bare "ACCENTURE" rows now depend on the address -------

def test_regression_without_dba_bare_names_follow_the_address(tmp_path):
    catalog = build_catalog(PARENT, ACCEPTED_SUBSIDIARIES, "", "", "")
    results = {
        r.column_b: r
        for r in validate_standard_rows(
            dataframe_to_rows(pd.DataFrame(ROWS)), catalog, NoWhoisClient(),
            search_client=ReplaySearchClient(), address_cache=AddressEvidenceCache(tmp_path),
        )
    }
    # Bare "Accenture" with an exact address found online -> TRUE Medium.
    assert (results["65.203.39.184/29"].column_e, results["65.203.39.184/29"].column_h) == ("TRUE", "Medium")
    # Bare "Accenture" with only city/state evidence -> FALSE.
    bare_not_found = ["23.251.193.112/30", "40.140.217.84/30", "40.140.217.148/30", "40.141.212.8/30",
                      "64.21.197.164/30", "66.77.1.0/24", "66.77.2.0/24", "66.77.5.0/24",
                      "67.208.150.56/29", "208.252.31.232/29"]
    for prefix in bare_not_found:
        assert (results[prefix].column_e, results[prefix].column_h) == ("FALSE", "Medium"), prefix
    # "Accenture US" is not listed anywhere -> no match.
    assert results["208.185.177.200/29"].match_type == "no_match"
    # "ACCENTURE LLP" rows are exact (listed as a subsidiary), so they are never a hard FALSE.
    for r in results.values():
        if "LLP" in r.column_c.upper():
            assert r.column_e == "TRUE" or r.column_h == "To Review", r.column_b
