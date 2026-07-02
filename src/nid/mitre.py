from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import read_json


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique: str
    tactic: str
    url: str
    description: str
    source: str = "category"

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "technique": self.technique,
            "tactic": self.tactic,
            "url": self.url,
            "description": self.description,
            "source": self.source,
        }


def map_attack(category: str, signature_ids: str | list[str] | None = None) -> list[dict[str, str]]:
    data = _mapping_data()
    techniques: list[MitreTechnique] = []
    by_id: dict[str, MitreTechnique] = {}
    for entries in data.get("categories", {}).values():
        for entry in entries:
            technique = _technique(entry, source="category")
            by_id[technique.technique_id] = technique

    for entry in data.get("categories", {}).get(category, []):
        techniques.append(_technique(entry, source="category"))

    for signature_id in _signature_list(signature_ids):
        for technique_id in data.get("signatures", {}).get(signature_id, []):
            if technique_id in by_id:
                base = by_id[technique_id]
                techniques.append(
                    MitreTechnique(
                        base.technique_id,
                        base.technique,
                        base.tactic,
                        base.url,
                        base.description,
                        source=f"signature:{signature_id}",
                    )
                )

    deduped: dict[str, MitreTechnique] = {}
    for technique in techniques:
        deduped.setdefault(technique.technique_id, technique)
    return [technique.to_dict() for technique in deduped.values()]


def mitre_summary(mappings: list[dict[str, str]]) -> dict[str, str]:
    tactics = sorted({item.get("tactic", "") for item in mappings if item.get("tactic")})
    techniques = [
        f"{item.get('technique_id', '')} {item.get('technique', '')}".strip()
        for item in mappings
        if item.get("technique_id")
    ]
    return {
        "mitre_tactics": ", ".join(tactics) if tactics else "None",
        "mitre_techniques": ", ".join(techniques) if techniques else "None",
        "mitre_technique_ids": ", ".join(item.get("technique_id", "") for item in mappings if item.get("technique_id")) or "None",
    }


def _mapping_data() -> dict[str, Any]:
    try:
        return read_json("configs/mitre_attack_mapping.json")
    except FileNotFoundError:
        return {"categories": {}, "signatures": {}}


def _technique(entry: dict[str, Any], source: str) -> MitreTechnique:
    return MitreTechnique(
        technique_id=str(entry.get("technique_id", "")),
        technique=str(entry.get("technique", "")),
        tactic=str(entry.get("tactic", "")),
        url=str(entry.get("url", "")),
        description=str(entry.get("description", "")),
        source=source,
    )


def _signature_list(signature_ids: str | list[str] | None) -> list[str]:
    if signature_ids is None:
        return []
    if isinstance(signature_ids, str):
        if signature_ids == "None":
            return []
        return [item.strip() for item in signature_ids.split(",") if item.strip()]
    return [str(item).strip() for item in signature_ids if str(item).strip()]
