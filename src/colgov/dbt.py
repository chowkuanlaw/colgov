"""Generate governed SQL views from dbt's manifest and complete catalog artifacts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from os import PathLike
from typing import Any

from colgov.policy import Policy
from colgov.review import Catalog
from colgov.sql import generate_view_sql

__all__ = ["DbtError", "DbtRelation", "generate_dbt_views", "load_dbt_relations"]


class DbtError(ValueError):
    """dbt artifacts cannot safely produce governed views."""


@dataclass(frozen=True)
class DbtRelation:
    table: str
    source: str
    columns: tuple[str, ...]
    identifier: str
    database: str


def _artifact(path: str | PathLike[str], kind: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise DbtError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DbtError(f"{path}: not a dbt {kind}.json artifact")
    metadata = data.get("metadata")
    if not isinstance(metadata, Mapping) or f"/{kind}/" not in str(metadata.get("dbt_schema_version", "")):
        raise DbtError(f"{path}: not a dbt {kind}.json artifact")
    return data


def _component(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value or "." in value or "\x00" in value:
        raise DbtError(f"{description} must be a non-empty SQL identifier without a dot or NUL")
    return value


def load_dbt_relations(manifest_path: str | PathLike[str], catalog_path: str | PathLike[str]) -> list[DbtRelation]:
    """Use catalog.json columns so undocumented manifest columns are not missed.

    Only materialized models, seeds, snapshots and sources with matching
    entries in both artifacts are included. Missing catalog entries fail
    closed; an incomplete manifest alone must never define a governed view.
    """
    manifest = _artifact(manifest_path, "manifest")
    catalog = _artifact(catalog_path, "catalog")
    result = []
    seen: set[str] = set()
    for section in ("nodes", "sources"):
        manifest_nodes = manifest.get(section) or {}
        catalog_nodes = catalog.get(section) or {}
        if not isinstance(manifest_nodes, Mapping) or not isinstance(catalog_nodes, Mapping):
            raise DbtError(f"{section} must be a mapping")
        for unique_id, node in manifest_nodes.items():
            kind = str(unique_id).partition(".")[0]
            if kind not in {"model", "seed", "snapshot", "source"}:
                continue
            if not isinstance(node, Mapping):
                raise DbtError(f"{unique_id}: invalid manifest node")
            config = node.get("config") or {}
            if isinstance(config, Mapping) and config.get("materialized") == "ephemeral":
                continue
            physical = catalog_nodes.get(unique_id)
            if not isinstance(physical, Mapping) or not isinstance(physical.get("columns"), Mapping):
                raise DbtError(f"{unique_id}: missing complete catalog.json columns")
            parts = str(unique_id).split(".")
            if kind == "source":
                source_name = _component(
                    node.get("source_name") or (parts[2] if len(parts) > 2 else None), f"{unique_id} source name"
                )
                name = _component(node.get("name"), f"{unique_id} name")
                table = f"{source_name}.{name}"
                identifier = node.get("identifier") or node.get("name")
            else:
                table = _component(node.get("name"), f"{unique_id} name")
                identifier = node.get("alias") or node.get("name")
            if table in seen:
                raise DbtError(f"{unique_id}: duplicate catalog table name {table!r}")
            seen.add(table)
            database = _component(node.get("database"), f"{unique_id} database")
            schema = _component(node.get("schema"), f"{unique_id} schema")
            identifier = _component(identifier, f"{unique_id} identifier")
            raw_columns = physical["columns"]
            columns = tuple(
                column.get("name") or key for key, column in raw_columns.items() if isinstance(column, Mapping)
            )
            if any(not isinstance(column, str) or not column or "\x00" in column for column in columns):
                raise DbtError(f"{unique_id}: catalog column names must be non-empty strings without NUL")
            if not columns or len(columns) != len(raw_columns) or len(set(columns)) != len(columns):
                raise DbtError(f"{unique_id}: catalog columns must have unique names")
            result.append(DbtRelation(table, f"{database}.{schema}.{identifier}", columns, identifier, database))
    if not result:
        raise DbtError("dbt artifacts contain no materialized relations")
    return result


def generate_dbt_views(
    relations: list[DbtRelation],
    policy: Policy,
    catalog: Catalog,
    *,
    role: str,
    view_schema: str,
    token_columns: Mapping[str, Mapping[str, str]] | None = None,
    dialect: str = "ansi",
) -> dict[str, str]:
    """Return SQL keyed by dbt table name; refuse unreviewed source columns."""
    view_schema = _component(view_schema, "view schema")
    mappings = token_columns or {}
    unknown = set(mappings) - {relation.table for relation in relations}
    if unknown:
        raise DbtError(f"token mappings name unknown dbt tables: {', '.join(sorted(unknown))}")
    views: dict[str, str] = {}
    destinations: set[str] = set()
    for relation in relations:
        mapped = mappings.get(relation.table, {})
        if not isinstance(mapped, Mapping) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in mapped.items()
        ):
            raise DbtError(f"{relation.table}: token mappings must be string-to-string")
        companions = set(mapped.values())
        pending = catalog.pending((c for c in relation.columns if c not in companions), table=relation.table)
        if pending:
            raise DbtError(f"{relation.table}: unreviewed columns: {', '.join(pending)}")
        view = f"{relation.database}.{view_schema}.{relation.identifier}"
        if view in destinations:
            raise DbtError(f"more than one dbt relation would create {view!r}")
        destinations.add(view)
        views[relation.table] = generate_view_sql(
            policy,
            catalog,
            role=role,
            columns=relation.columns,
            source=relation.source,
            view=view,
            token_columns=mapped,
            table=relation.table,
            dialect=dialect,
        )
    return views
