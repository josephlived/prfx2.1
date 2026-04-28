from __future__ import annotations

import io
import os
import time
from typing import Iterable, List

import pandas as pd
import streamlit as st
from openpyxl.styles import Alignment, Font

from domain_crawler import DomainEvidenceClient
from live_search import BraveSearchClient
from models import ValidationResult, WhoisOnlyResult
from address_evidence_cache import AddressEvidenceCache
from validator import build_catalog, dataframe_to_rows, validate_standard_rows, validate_whois_only_prefixes
from whois_lookup import WhoisLookupClient


st.set_page_config(page_title="Prefix Workbench", layout="wide")


def _read_secret(name: str) -> str:
    try:
        if name in st.secrets:
            return str(st.secrets[name] or "")
    except Exception:
        pass
    return ""


def _default_brave_api_key() -> str:
    return _read_secret("BRAVE_SEARCH_API_KEY")


def _brave_secret_status() -> str:
    return "Configured from Streamlit secrets" if _default_brave_api_key() else "Not configured in Streamlit secrets"


def _read_text_file(uploaded_file) -> str:
    return uploaded_file.getvalue().decode("utf-8-sig", errors="ignore")


def parse_company_upload(uploaded_file) -> List[str]:
    if uploaded_file is None:
        return []
    name = uploaded_file.name.lower()
    if name.endswith(".txt"):
        return [line.strip() for line in _read_text_file(uploaded_file).splitlines() if line.strip()]
    if name.endswith(".csv"):
        df = pd.read_csv(uploaded_file, header=None)
    elif name.endswith(".xlsx"):
        df = pd.read_excel(uploaded_file, header=None)
    else:
        raise ValueError("Unsupported subsidiary file type. Upload .txt, .csv, or .xlsx.")
    values: List[str] = []
    for value in df.iloc[:, 0].tolist():
        if pd.notna(value):
            text = str(value).strip()
            if text:
                values.append(text)
    return values


def parse_pasted_table(text: str) -> pd.DataFrame:
    cleaned = text.strip()
    if not cleaned:
        return pd.DataFrame()
    for separator in ("\t", ",", "|"):
        try:
            frame = pd.read_csv(io.StringIO(cleaned), sep=separator, header=None)
            if frame.shape[1] >= 2:
                return frame
        except Exception:
            continue
    raise ValueError("The pasted data could not be parsed. Use tab-, comma-, or pipe-delimited rows.")


def dataframe_from_upload(uploaded_file) -> pd.DataFrame:
    if uploaded_file is None:
        return pd.DataFrame()
    name = uploaded_file.name.lower()
    if name.endswith(".xlsx"):
        return pd.read_excel(uploaded_file, header=None)
    if name.endswith(".csv"):
        return pd.read_csv(uploaded_file, header=None)
    raise ValueError("Unsupported file type. Upload .xlsx or .csv.")


def results_to_dataframe(results: Iterable[ValidationResult]) -> pd.DataFrame:
    rows = []
    for result in results:
        rows.append(
            {
                "Analyst Decision": result.column_a,
                "Prefix": result.column_b,
                "Company Name": result.column_c,
                "Address": result.column_d,
                "Verdict": result.column_e,
                "Reason": result.column_f,
                "Matched Company Name": result.column_g,
                "Confidence": result.column_h,
                "Mismatch A vs E": "YES" if result.flag_mismatch else "",
                "Match Type": result.match_type,
                "Match Score": result.match_score,
                "WHOIS OrgName": result.whois_orgname,
                "WHOIS NetName": result.whois_netname,
                "WHOIS Domains": result.whois_domains,
                "WHOIS Addresses": result.whois_addresses,
                "WHOIS Registry": result.whois_registry,
            }
        )
    return pd.DataFrame(rows)


def whois_results_to_dataframe(results: Iterable[WhoisOnlyResult]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Input Prefix": result.input_prefix,
                "WHOIS OrgName": result.whois_orgname,
                "WHOIS NetName": result.whois_netname,
                "WHOIS Domains": result.whois_domains,
                "WHOIS Addresses": result.whois_addresses,
                "WHOIS Registry": result.whois_registry,
                "Matched Subsidiary": result.matched_subsidiary,
                "Match Type": result.match_type,
                "Match Score": result.match_score,
                "Verdict": result.verdict,
                "Reason": result.reason,
                "Confidence": result.confidence,
            }
            for result in results
        ]
    )


def export_standard_results(results: List[ValidationResult]) -> bytes:
    output = io.BytesIO()
    summary_df = results_to_dataframe(results)
    details_df = pd.DataFrame(
        [
            {
                "Row Number": result.row_number,
                "Audit Steps": "\n".join(result.audit_steps),
                "Review Reason": result.review_reason,
                "Source URL": result.source_url,
                "WHOIS Domains": result.whois_domains,
                "WHOIS Addresses": result.whois_addresses,
                "WHOIS Registry": result.whois_registry,
                "Live Search Debug": result.live_search_debug,
            }
            for result in results
        ]
    )
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        summary_df.to_excel(writer, index=False, sheet_name="Results")
        details_df.to_excel(writer, index=False, sheet_name="Audit Trail")
        for worksheet in writer.book.worksheets:
            worksheet.freeze_panes = "A2"
            for row in worksheet.iter_rows():
                for cell in row:
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
            for cell in worksheet[1]:
                cell.font = Font(bold=True)
            for column_cells in worksheet.columns:
                max_length = 0
                column_letter = column_cells[0].column_letter
                for cell in column_cells:
                    value = "" if cell.value is None else str(cell.value)
                    if len(value) > max_length:
                        max_length = len(value)
                worksheet.column_dimensions[column_letter].width = min(max(max_length + 2, 14), 70)
    return output.getvalue()


def render_progress_section(title: str):
    progress_bar = st.progress(0, text=title)
    status_placeholder = st.empty()
    elapsed_placeholder = st.empty()
    return progress_bar, status_placeholder, elapsed_placeholder


st.title("Prefix Workbench")
st.caption("Two-mode validator: structured row validation plus a WHOIS-only prefix mode.")

with st.sidebar:
    st.header("Entity Inputs")
    parent_company = st.text_input("Parent Company")
    subsidiaries_upload = st.file_uploader(
        "Upload Accepted Subsidiaries",
        type=["txt", "csv", "xlsx"],
        help="Recommended: .txt with one accepted company per line. .csv/.xlsx uses the first column only.",
        key="subsidiaries-upload",
    )
    subsidiaries_text = st.text_area(
        "Accepted Subsidiaries",
        height=180,
        placeholder="One accepted company per line",
    )
    aliases_text = st.text_area(
        "Alias / DBA Overrides",
        height=120,
        placeholder="Format: Alias => Canonical Name",
    )
    accepted_domains_text = st.text_area(
        "Accepted Domains",
        height=120,
        placeholder="One domain per line, optionally: domain.com | Company Name",
        help="Used as WHOIS/RDAP corroboration first; optional web crawl/search evidence only runs after that.",
    )
    brave_search_api_key = _default_brave_api_key()
    st.caption(f"Brave Search API key: {_brave_secret_status()}")
    verify_whois_addresses = st.checkbox(
        "Verify WHOIS addresses with live search",
        value=False,
        help="Slower. When enabled, exact WHOIS name matches without accepted-domain evidence can be corroborated with web search.",
    )
    address_book_text = st.text_area(
        "Known Address Evidence",
        height=180,
        placeholder="Format: Company | Address | URL (URL optional)",
        help="Use this zero-cost address book to prove exact address matches without paid search APIs.",
    )

uploaded_subsidiaries = parse_company_upload(subsidiaries_upload) if subsidiaries_upload is not None else []
combined_subsidiaries_text = subsidiaries_text
if uploaded_subsidiaries:
    combined_subsidiaries_text = "\n".join([*uploaded_subsidiaries, subsidiaries_text.strip()]) if subsidiaries_text.strip() else "\n".join(uploaded_subsidiaries)

catalog = build_catalog(parent_company, combined_subsidiaries_text, aliases_text, address_book_text, accepted_domains_text)
whois_client = WhoisLookupClient()
domain_client = DomainEvidenceClient()
search_client = BraveSearchClient(brave_search_api_key)
address_cache = AddressEvidenceCache()
cache_stats = whois_client.cache_stats()
crawl_cache_stats = domain_client.cache_stats()
search_cache_stats = search_client.cache_stats()
address_cache_stats = address_cache.cache_stats()

with st.sidebar:
    st.caption(f"Accepted entities loaded: {len(catalog.accepted_entities)}")
    st.caption(f"Accepted domains loaded: {len(catalog.accepted_domains)}")
    st.caption(f"Domain crawl engine: {domain_client.engine_label()}")
    st.caption(f"Live search engine: {search_client.engine_label()}")
    if subsidiaries_upload is not None:
        st.caption(f"Uploaded subsidiary rows loaded: {len(uploaded_subsidiaries)}")
    st.divider()
    st.subheader("Cache")
    st.caption(f"WHOIS cache entries: {cache_stats['entries']}")
    st.caption(f"WHOIS cache file: {cache_stats['path']}")
    if st.button("Clear WHOIS Cache"):
        whois_client.clear_cache()
        st.success("WHOIS cache cleared.")
        st.rerun()
    st.caption(f"Domain crawl cache entries: {crawl_cache_stats['entries']}")
    st.caption(f"Domain crawl cache file: {crawl_cache_stats['path']}")
    if st.button("Clear Domain Crawl Cache"):
        domain_client.clear_cache()
        st.success("Domain crawl cache cleared.")
        st.rerun()
    st.caption(f"Live search cache entries: {search_cache_stats['entries']}")
    st.caption(f"Live search cache file: {search_cache_stats['path']}")
    if st.button("Clear Live Search Cache"):
        search_client.clear_cache()
        st.success("Live search cache cleared.")
        st.rerun()
    st.caption(f"Address evidence cache entries: {address_cache_stats['entries']}")
    st.caption(f"Address evidence cache file: {address_cache_stats['path']}")
    if st.button("Clear Address Evidence Cache"):
        address_cache.clear_cache()
        st.success("Address evidence cache cleared.")
        st.rerun()
    if st.button("Test Brave API Key"):
        ok, message = search_client.validate_key()
        if ok:
            st.success(message)
        else:
            st.error(f"Brave API test failed: {message}")
    if not whois_client.is_available():
        st.warning("WHOIS is disabled because `ipwhois` is not installed in this environment.")

tab_standard, tab_whois = st.tabs(["Standard Validator", "WHOIS-Only Prefix Validator"])

with tab_standard:
    st.subheader("Standard Validator")
    st.write("Upload a worksheet or paste rows. The engine maps the first four columns to A-D, can crawl accepted domains for exact address evidence, and can optionally escalate to live search.")
    if not domain_client.browser_available():
        st.info("Accepted-domain crawl is currently using HTTP fallback because Playwright is not installed in this Python environment.")
    if not search_client.is_configured():
        st.caption("Live search is disabled until you provide a Brave Search API key.")
    else:
        st.caption("Live search runs only for rows that have both a usable company name and a usable address, and only after cheaper evidence paths fail.")
    upload = st.file_uploader("Upload .xlsx or .csv", type=["xlsx", "csv"], key="standard-upload")
    if upload is not None:
        st.caption(f"Loaded file: {upload.name}")
    pasted_rows = st.text_area(
        "Paste Rows",
        height=220,
        placeholder="Paste tab-, comma-, or pipe-delimited rows here",
    )
    run_standard = st.button("Run Standard Validation", type="primary")

    if run_standard:
        try:
            source_df = dataframe_from_upload(upload) if upload is not None else parse_pasted_table(pasted_rows)
            if source_df.empty:
                st.error("Provide an upload or paste rows before running validation.")
            elif not catalog.accepted_entities:
                st.error("Provide the parent company and/or accepted subsidiaries first.")
            else:
                progress_bar, status_placeholder, elapsed_placeholder = render_progress_section("Starting standard validation...")
                started_at = time.perf_counter()

                def report_progress(done: int, total: int, message: str) -> None:
                    ratio = 0 if total == 0 else done / total
                    progress_bar.progress(ratio, text=f"{done}/{total} rows processed")
                    status_placeholder.info(message)
                    elapsed_placeholder.caption(f"Elapsed: {time.perf_counter() - started_at:.1f}s")

                with st.spinner("Running standard validation..."):
                    rows = dataframe_to_rows(source_df)
                    total_rows = len(rows)
                    progress_bar.progress(0, text=f"0/{total_rows} rows processed")
                    results = validate_standard_rows(
                        rows,
                        catalog,
                        whois_client,
                        domain_client=domain_client,
                        search_client=search_client,
                        verify_whois_addresses=verify_whois_addresses,
                        progress_callback=report_progress,
                    )
                progress_bar.progress(1.0, text=f"{len(results)}/{len(results)} rows processed")
                status_placeholder.success("Standard validation complete.")
                elapsed_placeholder.caption(f"Elapsed: {time.perf_counter() - started_at:.1f}s")
                result_df = results_to_dataframe(results)
                mismatch_count = sum(result.flag_mismatch for result in results)
                left, right = st.columns(2)
                left.metric("Rows Processed", len(results))
                right.metric("Analyst vs Engine Mismatches", mismatch_count)
                if not whois_client.is_available():
                    st.info("WHOIS-dependent cases will stay FALSE until `ipwhois` is installed. Address-book and deterministic rules still work.")
                st.dataframe(result_df, use_container_width=True)
                st.download_button(
                    "Download Results.xlsx",
                    data=export_standard_results(results),
                    file_name="validation-results.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
                st.markdown("**Per-row audit**")
                for result in results:
                    header = f"Row {result.row_number} | Engine={result.column_e} | Analyst={result.column_a or '[blank]'}"
                    if result.flag_mismatch:
                        header += " | MISMATCH"
                    with st.expander(header):
                        for step in result.audit_steps:
                            st.write(step)
        except Exception as exc:
            st.error(str(exc))

with tab_whois:
    st.subheader("WHOIS-Only Prefix Validator")
    st.write("Paste one prefix/IP per line. This mode uses WHOIS/RDAP only and compares OrgName/NetName to your accepted company list.")
    prefixes_text = st.text_area(
        "Prefixes / IPs",
        height=240,
        placeholder="12.14.184.160/29\n216.204.240.136/29",
    )
    run_whois = st.button("Run WHOIS-Only Validation", type="primary")

    if run_whois:
        prefixes = [line.strip() for line in prefixes_text.splitlines() if line.strip()]
        if not prefixes:
            st.error("Paste at least one prefix/IP before running WHOIS-only validation.")
        elif not catalog.accepted_entities:
            st.error("Provide the parent company and/or accepted subsidiaries first.")
        elif not whois_client.is_available():
            st.error("WHOIS-only mode cannot run yet because `ipwhois` is not installed.")
        else:
            progress_bar, status_placeholder, elapsed_placeholder = render_progress_section("Starting WHOIS-only validation...")
            started_at = time.perf_counter()

            def report_progress(done: int, total: int, message: str) -> None:
                ratio = 0 if total == 0 else done / total
                progress_bar.progress(ratio, text=f"{done}/{total} prefixes processed")
                status_placeholder.info(message)
                elapsed_placeholder.caption(f"Elapsed: {time.perf_counter() - started_at:.1f}s")

            with st.spinner("Running WHOIS-only validation..."):
                total_prefixes = len(prefixes)
                progress_bar.progress(0, text=f"0/{total_prefixes} prefixes processed")
                results = validate_whois_only_prefixes(
                    prefixes,
                    catalog,
                    whois_client,
                    search_client=search_client,
                    verify_whois_addresses=verify_whois_addresses,
                    progress_callback=report_progress,
                )
            progress_bar.progress(1.0, text=f"{len(results)}/{len(results)} prefixes processed")
            status_placeholder.success("WHOIS-only validation complete.")
            elapsed_placeholder.caption(f"Elapsed: {time.perf_counter() - started_at:.1f}s")
            st.dataframe(whois_results_to_dataframe(results), use_container_width=True)
            with st.expander("Mode Notes"):
                st.write("WHOIS-only TRUE results come from exact/approved-alias WHOIS name matches, or from very close WHOIS names corroborated by an accepted domain.")
                st.write("Very close WHOIS names without domain corroboration are flagged as To Review and remain FALSE.")
