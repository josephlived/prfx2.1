# Prefix Workbench

A Streamlit app for validating whether an IP prefix's registered owner matches an accepted parent company or one of its subsidiaries. The main path is WHOIS/RDAP-first: it checks the most-specific customer/org names, NetName, accepted domains, and WHOIS address fields before using local address evidence or optional web/search corroboration.

## Two Modes

### Standard Validator

Takes a spreadsheet or pasted table whose first four columns map to:

| Col | Meaning |
|-----|---------|
| A | Analyst decision (`TRUE` / `FALSE` - optional, used only to flag mismatches) |
| B | Prefix / IP |
| C | Raw company name, optional |
| D | Raw address, optional |

For each row the engine runs this pipeline, stopping at the first decisive hit:

1. **WHOIS / RDAP** for the prefix. Exact or approved-alias customer/org/NetName matches are TRUE; accepted-domain evidence in WHOIS raises confidence.
2. **WHOIS close-name + accepted-domain corroboration** -> TRUE with medium/high confidence depending on evidence.
3. **WHOIS close-name without domain corroboration** -> To Review, Verdict FALSE.
4. **WHOIS accepted-domain only, without accepted entity name** -> To Review, Verdict FALSE.
5. **Exact known-address match** against the pasted address book (`Company | Address | URL`).
6. **Private address** + exact company name -> TRUE.
7. **Known data-center address** (hard-coded list in `validator.py`) + exact company name -> TRUE.
8. **Coarse location match** (same state/country) against address-book entries for the matched company.
9. **Accepted-domain crawl** - fetches `/`, `/contact`, `/locations`, etc. on each accepted domain and checks for the address (Playwright if installed, HTTP fallback otherwise).
10. **Live search** via the Brave Search API. It is optional and mainly used for unresolved cases or when "Verify WHOIS addresses with live search" is enabled.

### WHOIS-Only Prefix Validator

Paste prefixes/IPs, one per line. Runs RDAP lookups and compares customer/org names, NetName, linked domains, and address fields against the accepted catalog. TRUE comes from exact/alias WHOIS name matches, or close WHOIS name matches corroborated by an accepted domain. Domain-only evidence is emitted as **To Review**.

## Output Columns

| Col | Meaning |
|-----|---------|
| E | Verdict - `TRUE` / `FALSE` |
| F | Reason with optional source URL |
| G | Matched subsidiary / accepted company |
| H | Confidence - `High` / `Medium` / `To Review` |

The Excel export adds an **Audit Trail** sheet with the 10-step per-row audit, WHOIS evidence, and live-search debug log when present.

## Inputs (Sidebar)

| Field | Format |
|-------|--------|
| Parent Company | Free text |
| Accepted Subsidiaries | One per line, or upload `.txt` / `.csv` / `.xlsx` (first column) |
| Alias / DBA Overrides | `Alias => Canonical Name` (also accepts `->`, `|`, `=`) |
| Accepted Domains | One per line, optionally `domain.com | Company Name` |
| Brave Search API Key | Optional; enables web address corroboration. Can also be set via `BRAVE_SEARCH_API_KEY`. |
| Verify WHOIS Addresses With Live Search | Optional, slower; corroborates WHOIS address fields on the web when domain evidence is absent. |
| Known Address Evidence | `Company | Address | URL` per line (URL optional) |

## Run

```bash
pip install -r requirements.txt
# Optional: enables JS-rendered domain crawl. Without it, HTTP fallback is used.
playwright install chromium
streamlit run app.py
```

`ipwhois` is an optional runtime dependency; if it is missing, WHOIS-dependent paths stay FALSE but all other checks still work.

## File Map

| File | Role |
|------|------|
| `app.py` | Streamlit UI, file parsing, Excel export |
| `validator.py` | Pipeline orchestration (`validate_standard_rows`, `validate_whois_only_prefixes`), known data-center list |
| `matching.py` | Company/address normalization, alias parsing, fuzzy scoring, coarse location match |
| `domain_crawler.py` | Accepted-domain crawl (Playwright preferred, HTTP fallback) |
| `live_search.py` | Brave Search API client, snippet/page address matching, on-disk cache |
| `whois_lookup.py` | RDAP via `ipwhois`, customer/org names, NetName, domain/address extraction, cache |
| `models.py` | Dataclasses: `CompanyCatalog`, `InputRow`, `ValidationResult`, `WhoisRecord`, `WhoisOnlyResult`, `AddressEvidence` |
| `requirements.txt` | Python dependencies |

## Caches

WHOIS, domain-crawl, and live-search results are cached on disk under `cache/`. Each cache has its own **Clear** button in the sidebar.

## Notes

- Normalization lower-cases, strips punctuation, expands common address abbreviations (`st` -> `street`, `se` -> `southeast`, `cir` -> `circle`, `united states` -> `us`, etc.), and expands safe company abbreviations (`intl` -> `international`).
- Company matching accepts exact matches, alias-table hits, acronym matches, suffix-stripped matches, and a rapidfuzz score >= 97.
- The engine does not upgrade accepted-domain-only evidence to TRUE unless a WHOIS name also matches or closely matches an accepted company.
