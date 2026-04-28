from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from matching import classify_company_match, normalize_address
from models import CompanyCatalog


class AddressEvidenceCache:
    def __init__(self, cache_dir: str | Path = "cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "address_evidence_cache.json"

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self, cache_data: dict[str, Any]) -> None:
        self.cache_path.write_text(json.dumps(cache_data, indent=2, ensure_ascii=True), encoding="utf-8")

    def clear_cache(self) -> None:
        if self.cache_path.exists():
            self.cache_path.unlink()

    def cache_stats(self) -> dict[str, Any]:
        cache = self._load_cache()
        return {
            "entries": len(cache),
            "path": str(self.cache_path),
        }

    def get(self, address: str, catalog: CompanyCatalog) -> Optional[dict[str, Any]]:
        normalized = normalize_address(address)
        if not normalized:
            return None
        record = self._load_cache().get(normalized)
        if not isinstance(record, dict):
            return None
        owner = str(record.get("matched_accepted_entity", "")).strip()
        matched, _, _ = classify_company_match(owner, catalog)
        if not matched:
            return None
        record["matched_accepted_entity"] = matched
        return record

    def put(
        self,
        address: str,
        matched_accepted_entity: str,
        source_url: str,
        evidence_type: str,
        confidence: str,
    ) -> None:
        normalized = normalize_address(address)
        if not normalized or not matched_accepted_entity.strip() or not source_url.strip():
            return
        cache = self._load_cache()
        cache[normalized] = {
            "normalized_address": normalized,
            "matched_accepted_entity": matched_accepted_entity,
            "source_url": source_url,
            "evidence_type": evidence_type,
            "confidence": confidence,
            "verified_at": datetime.now(timezone.utc).date().isoformat(),
        }
        self._save_cache(cache)
