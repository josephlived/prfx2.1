"""Regression fixture: 25 real rows from two analyst-reviewed validation runs.

Each row is (analyst_decision, prefix, raw_company_name, raw_address). The
company/address values are public ARIN registry data for each prefix.

RECORDED_SEARCH maps an address to what Brave live search returned for it in
those runs: (url, mode). mode is "exact_address" or "state_country". Addresses
not listed returned nothing. Tests replay these results offline so they never
call the network or spend Brave credit.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

from matching import normalize_address

ACCEPTED_SUBSIDIARIES = "Accenture Plc\nAccenture LLP\nAccenture"

ROWS = [
    # File 1 (validation-results_3.xlsx)
    ("TRUE", "12.156.227.136/29", "ACCENTURE LLP,", "11250 CORPORATE AVE LENEXA KS 66219 US,"),
    ("TRUE", "12.188.169.208/28", "ACCENTURE LLP,", "10815 DAVID TAYLOR DR CHAR NC 28262 US,"),
    ("FALSE", "23.251.193.112/30", "Accenture,", "670 E Gilbert St San Bernardino CA 92415 US,"),
    ("TRUE", "40.140.217.84/30", "ACCENTURE,", "3301 BENSON DR RALEIGH NC 27609-7362 US,"),
    ("TRUE", "40.140.217.148/30", "ACCENTURE,", "3301 BENSON DR RALEIGH NC 27609-7362 US,"),
    ("TRUE", "40.141.212.8/30", "ACCENTURE,", "3301 BENSON DR RALEIGH NC 27609-7362 US,"),
    ("TRUE", "64.21.197.164/30", "ACCENTURE,", "220 S LASSEN ST SUSANVILLE CA 96130 US,"),
    ("TRUE", "65.203.39.184/29", "Addresses within this block are non-portable.,Accenture,", "1610 R ST SACRAMENTO CA 95811-6676 US,"),
    ("TRUE", "65.205.134.216/29", "Addresses within this block are non-portable.,ACCENTURE LLP,", "75 5TH ST NW ATLANTA GA 30308 US,"),
    ("TRUE", "65.214.176.168/29", "Addresses within this block are non-portable.,ACCENTURE LLP,", "800 CORPORATE POINTE CULVER CITY CA 90230-7667 US,"),
    ("TRUE", "65.216.182.0/28", "Addresses within this block are non-portable.,ACCENTURE LLP,", "1201 WILSON BLVD ARLINGTON VA 22209 US,"),
    ("TRUE", "65.242.38.96/29", "Addresses within this block are non-portable.,ACCENTURE LLP,", "1201 WILSON BLVD ARLINGTON VA 22209-2304 US,"),
    ("TRUE", "66.77.1.0/24", "Accenture,", "6560 South Greenwood Plaza Blvd. Englewood CO 80111 US,"),
    ("TRUE", "66.77.2.0/24", "Accenture,", "6560 South Greenwood Plaza Blvd. Englewood CO 80111 US,"),
    ("TRUE", "66.77.5.0/24", "Accenture,", "6560 South Greenwood Plaza Blvd. Englewood CO 80111 US,"),
    ("TRUE", "67.208.150.56/29", "Accenture,", "201 East 4th St. Suite 1600 Cincinnati OH 45202 US,"),
    ("TRUE", "131.226.234.32/27", "ACCENTURE LLP,", "2425 Busse Road Elk Grove Village IL 60007-5737 US,"),
    # File 2 (validation-results_4.xlsx)
    ("TRUE", "131.226.237.0/24", "ACCENTURE LLP,", "2425 Busse Road Elk Grove Village IL 60007-5737 US,"),
    ("TRUE", "152.193.173.184/30", "ACCENTURE LLP,", "1865 MCFARLAND PKWY ALPHARETTA GA 30005-1712 US,"),
    ("TRUE", "173.252.132.152/30", "Accenture LLP,", "c/o SGNS, 401 N. Broad St. Philadelphia PA 19106 US,"),
    ("TRUE", "173.252.132.156/30", "Accenture LLP,", "c/o SGNS, 401 N. Broad St. Philadelphia PA 19106 US,"),
    ("TRUE", "206.136.82.208/29", "ACCENTURE LLP,", "909 LOCUST ST DES MOINES IA 50309-2801 US,"),
    ("FALSE", "208.185.177.200/29", "1,Accenture US,", "1095 Avenue of the Americas New York NY 10036 US,"),
    ("TRUE", "208.244.7.8/29", "ACCENTURE LLP,", "7777 BONHOMME AVE CLAYTON MO 63105-1911 US,"),
    ("TRUE", "208.252.31.232/29", "ACCENTURE,Addresses within this block are non-portable.,", "888 BOYLSTON ST BOSTON MA 02199-8192 US,"),
]

_RECORDED = {
    "11250 CORPORATE AVE LENEXA KS 66219 US": ("https://meetbeagle.com/my-401k-login/CITYWIDE-HOME-LOANS--LLC-401k-login-85576", "state_country"),
    "670 E Gilbert St San Bernardino CA 92415 US": ("https://swaaae.org/Board-of-Directors", "state_country"),
    "3301 BENSON DR RALEIGH NC 27609-7362 US": ("https://www.indeed.com/viewjob?jk=fad643fa4fcc9277", "state_country"),
    "220 S LASSEN ST SUSANVILLE CA 96130 US": ("https://veripages.com/name/James/Petropoulos/", "state_country"),
    "1610 R ST SACRAMENTO CA 95811-6676 US": ("https://opengovus.com/sacramento-business/74193", "exact_address"),
    "75 5TH ST NW ATLANTA GA 30308 US": ("https://www.buzzfile.com/business/Accenture-LLP-678-657-8000", "exact_address"),
    "800 CORPORATE POINTE CULVER CITY CA 90230-7667 US": ("https://www.dnb.com/business-directory/company-profiles.accenture_llp.cd2901870fafc9e0cc1cf48d54e5abe1.html", "state_country"),
    "1201 WILSON BLVD ARLINGTON VA 22209 US": ("https://web.novachamber.org/Accenture-LLP-7032", "exact_address"),
    "1201 WILSON BLVD ARLINGTON VA 22209-2304 US": ("https://opengovus.com/sam-entity/NKF4GENK83K4", "state_country"),
    "6560 South Greenwood Plaza Blvd. Englewood CO 80111 US": ("https://co.allpages.com/englewood/business-services/management-consultants-services/", "state_country"),
    "201 East 4th St. Suite 1600 Cincinnati OH 45202 US": ("https://www.yellowpages.com/cincinnati-oh/mip/accenture-475909451", "state_country"),
    "2425 Busse Road Elk Grove Village IL 60007-5737 US": ("https://www.accenture.com/content/dam/accenture/final/careers/careers-materials/LCA/Document/69e78e8775b20e001c5d647d-15-1211-McDonalds-Chicago-Illinois-Elk-Grove-Village-Illinois-5-Aug-2029.pdf", "state_country"),
    "888 BOYLSTON ST BOSTON MA 02199-8192 US": ("https://www.accenture.com/en/about/location", "state_country"),
}

RECORDED_SEARCH = {normalize_address(address): result for address, result in _RECORDED.items()}


class ReplaySearchClient:
    """Stands in for BraveSearchClient, replaying the recorded results."""

    def __init__(self, recorded: Optional[dict] = None) -> None:
        self.recorded = RECORDED_SEARCH if recorded is None else recorded
        self.calls: list[Tuple[str, str]] = []

    def is_configured(self) -> bool:
        return True

    def find_address_evidence(
        self,
        company_name: str,
        address: str,
        accepted_domains: Iterable[str],
        related_company_names: Iterable[str] = (),
    ) -> Tuple[Optional[str], str, str, str]:
        self.calls.append((company_name, address))
        hit = self.recorded.get(normalize_address(address))
        if hit:
            url, mode = hit
            return url, mode, "", f"replayed {mode} {url}"
        return None, "", "Live search did not find address or location evidence on the searched pages.", "replayed miss"


class NoWhoisClient:
    """Fails loudly if a row that already has name + address hits RDAP."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def is_available(self) -> bool:
        return True

    def lookup(self, prefix: str):  # pragma: no cover - only hit on a regression
        self.calls.append(prefix)
        raise AssertionError(f"RDAP should not be called for {prefix}: the row already has a name and address")
