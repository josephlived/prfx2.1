"""Live search must keep looking for exact-address evidence after a city/state-only hit."""

from live_search import BraveSearchClient

ADDRESS = "909 Locust St, Des Moines, IA 50309 US"  # registry addresses end with the country


def make_client(tmp_path, results):
    client = BraveSearchClient("test-key", cache_dir=tmp_path)
    client._search = lambda query: (results, "")
    client._fetch_page = lambda url: ("", "fetch blocked")
    return client


def test_exact_hit_after_location_only_hit_wins(tmp_path):
    results = [
        {"url": "https://directory.test/des-moines", "title": "Accenture LLP", "description": "Accenture offices in Des Moines, IA"},
        {"url": "https://bidopportunities.iowa.test/vendor", "title": "Accenture LLP vendor",
         "description": "Accenture LLP vendor address 909 Locust St Des Moines IA 50309"},
    ]
    url, mode, error, _ = make_client(tmp_path, results).find_address_evidence("Accenture LLP", ADDRESS, [])
    assert (url, mode) == ("https://bidopportunities.iowa.test/vendor", "exact_address")


def test_location_only_hit_is_reported_as_location_only(tmp_path):
    results = [{"url": "https://directory.test/des-moines", "title": "Accenture LLP", "description": "Accenture offices in Des Moines, IA"}]
    url, mode, _, _ = make_client(tmp_path, results).find_address_evidence("Accenture LLP", ADDRESS, [])
    assert (url, mode) == ("https://directory.test/des-moines", "state_country")
