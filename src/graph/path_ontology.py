"""Frozen controlled vocabulary for cloud data path nodes and edges."""
from __future__ import annotations

from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Literal, Mapping


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ONTOLOGY_PATH = ROOT / "configs" / "path_ontology_v1.json"
TypeKind = Literal["node", "edge"]


@lru_cache(maxsize=8)
def load_path_ontology(
    path: str | Path = DEFAULT_ONTOLOGY_PATH,
) -> dict[str, Any]:
    resolved = Path(path).resolve()
    raw = resolved.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    _validate_ontology(value)
    value["_path"] = str(resolved)
    value["_sha256"] = sha256(raw).hexdigest()
    return value


def ontology_reference(
    path: str | Path = DEFAULT_ONTOLOGY_PATH,
) -> dict[str, str]:
    ontology = load_path_ontology(path)
    return {
        "ontology_id": ontology["ontology_id"],
        "version": ontology["version"],
        "sha256": ontology["_sha256"],
    }


def policy_ontology_contract() -> dict[str, Any]:
    ontology = load_path_ontology()
    return {
        **ontology_reference(),
        "require_canonical_ids": True,
        "node_types": [
            {
                "id": item["id"],
                "definition": item["definition"],
            }
            for item in ontology["node_types"]
        ],
        "edge_types": [
            {
                "id": item["id"],
                "definition": item["definition"],
            }
            for item in ontology["edge_types"]
        ],
    }


def canonicalize_type(
    value: Any,
    kind: TypeKind,
    *,
    allow_alias: bool,
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    token = normalize_type_token(value)
    index = _type_index(kind)
    canonical = index["aliases"].get(token)
    if canonical is None:
        return None
    if not allow_alias and value.strip() != canonical:
        return None
    return canonical


def suggested_canonical_type(value: Any, kind: TypeKind) -> str | None:
    return canonicalize_type(value, kind, allow_alias=True)


def coarse_type(value: Any, kind: TypeKind) -> str | None:
    canonical = canonicalize_type(value, kind, allow_alias=True)
    if canonical is None:
        return None
    return _type_index(kind)["families"][canonical]


def validate_canonical_gold_types(case: Mapping[str, Any]) -> list[str]:
    errors = []
    for index, node in enumerate(case.get("nodes") or []):
        value = node.get("type") if isinstance(node, Mapping) else None
        if canonicalize_type(value, "node", allow_alias=False) is None:
            suggestion = suggested_canonical_type(value, "node")
            errors.append(
                f"nodes[{index}].type must be a canonical ontology ID"
                + (f"; use {suggestion}" if suggestion else "")
            )
    for index, edge in enumerate(case.get("edges") or []):
        value = edge.get("type") if isinstance(edge, Mapping) else None
        if canonicalize_type(value, "edge", allow_alias=False) is None:
            suggestion = suggested_canonical_type(value, "edge")
            errors.append(
                f"edges[{index}].type must be a canonical ontology ID"
                + (f"; use {suggestion}" if suggestion else "")
            )
    return errors


def normalize_type_token(value: str) -> str:
    token = value.strip().casefold()
    token = re.sub(r"[\s-]+", "_", token)
    token = re.sub(r"[^a-z0-9_]+", "", token)
    return re.sub(r"_+", "_", token).strip("_")


@lru_cache(maxsize=2)
def _type_index(kind: TypeKind) -> dict[str, dict[str, str]]:
    ontology = load_path_ontology()
    items = ontology[f"{kind}_types"]
    aliases: dict[str, str] = {}
    families: dict[str, str] = {}
    for item in items:
        canonical = item["id"]
        families[canonical] = item["family"]
        for raw in [canonical, *item.get("aliases", [])]:
            token = normalize_type_token(raw)
            existing = aliases.get(token)
            if existing is not None and existing != canonical:
                raise ValueError(
                    f"{kind} alias {raw!r} maps to both "
                    f"{existing} and {canonical}"
                )
            aliases[token] = canonical
    return {"aliases": aliases, "families": families}


def _validate_ontology(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("path ontology root must be an object")
    for key in ("ontology_id", "version", "node_types", "edge_types"):
        if key not in value:
            raise ValueError(f"path ontology lacks {key}")
    if not isinstance(value["ontology_id"], str) or not value["ontology_id"]:
        raise ValueError("path ontology ID is invalid")
    for kind in ("node", "edge"):
        items = value[f"{kind}_types"]
        if not isinstance(items, list) or not items:
            raise ValueError(f"path ontology {kind}_types must be non-empty")
        ids = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"path ontology {kind} entry is invalid")
            for key in ("id", "family", "definition", "aliases"):
                if key not in item:
                    raise ValueError(
                        f"path ontology {kind} entry lacks {key}"
                    )
            canonical = item["id"]
            if (
                not isinstance(canonical, str)
                or normalize_type_token(canonical) != canonical
            ):
                raise ValueError(
                    f"path ontology {kind} ID is not canonical: {canonical}"
                )
            if not isinstance(item["aliases"], list):
                raise ValueError(f"path ontology {kind} aliases must be a list")
            ids.append(canonical)
        if len(ids) != len(set(ids)):
            raise ValueError(f"path ontology has duplicate {kind} IDs")
