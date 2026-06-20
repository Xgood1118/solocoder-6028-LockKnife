from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from lockknife.core._case_common import load_case_manifest
from lockknife.core._case_models import CaseArtifact, CaseManifest
from lockknife.core._case_store import CaseStore, EventRecord


@dataclasses.dataclass
class DiffEntry:
    kind: str
    field: str
    old_value: Any
    new_value: Any
    detail: str = ""


@dataclasses.dataclass
class DiffGroup:
    section: str
    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    modified: list[dict[str, Any]]


@dataclasses.dataclass
class CaseDiffResult:
    case_a: str
    case_b: str
    manifest_diff: DiffGroup
    artifacts_diff: DiffGroup
    custody_diff: DiffGroup
    summary: dict[str, int]


def _diff_manifest_fields(a: CaseManifest, b: CaseManifest) -> DiffGroup:
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []

    simple_fields = [
        "case_id",
        "title",
        "examiner",
        "notes",
        "schema_version",
        "workspace_root",
        "created_at_utc",
        "updated_at_utc",
    ]
    for field in simple_fields:
        val_a = getattr(a, field)
        val_b = getattr(b, field)
        if val_a != val_b:
            modified.append(
                {
                    "field": field,
                    "old_value": val_a,
                    "new_value": val_b,
                }
            )

    set_fields = [
        ("target_serials", "target_serial"),
    ]
    for field, label in set_fields:
        set_a = set(getattr(a, field))
        set_b = set(getattr(b, field))
        for item in sorted(set_b - set_a):
            added.append({"field": label, "value": item})
        for item in sorted(set_a - set_b):
            removed.append({"field": label, "value": item})

    return DiffGroup(
        section="manifest",
        added=added,
        removed=removed,
        modified=modified,
    )


def _artifact_to_dict(artifact: CaseArtifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "path": artifact.path,
        "category": artifact.category,
        "source_command": artifact.source_command,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size_bytes,
        "created_at_utc": artifact.created_at_utc,
        "device_serial": artifact.device_serial,
        "input_paths": artifact.input_paths,
        "parent_artifact_ids": artifact.parent_artifact_ids,
        "metadata": artifact.metadata,
    }


def _diff_artifacts(a: CaseManifest, b: CaseManifest) -> DiffGroup:
    artifacts_a = {art.artifact_id: art for art in a.artifacts}
    artifacts_b = {art.artifact_id: art for art in b.artifacts}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []

    for aid in sorted(artifacts_b.keys() - artifacts_a.keys()):
        added.append(_artifact_to_dict(artifacts_b[aid]))

    for aid in sorted(artifacts_a.keys() - artifacts_b.keys()):
        removed.append(_artifact_to_dict(artifacts_a[aid]))

    for aid in sorted(artifacts_a.keys() & artifacts_b.keys()):
        art_a = artifacts_a[aid]
        art_b = artifacts_b[aid]
        changes: list[dict[str, Any]] = []
        for field in (
            "path",
            "category",
            "source_command",
            "sha256",
            "size_bytes",
            "created_at_utc",
            "device_serial",
            "input_paths",
            "parent_artifact_ids",
            "metadata",
        ):
            val_a = getattr(art_a, field)
            val_b = getattr(art_b, field)
            if val_a != val_b:
                changes.append({"field": field, "old_value": val_a, "new_value": val_b})
        if changes:
            modified.append(
                {
                    "artifact_id": aid,
                    "changes": changes,
                }
            )

    return DiffGroup(
        section="artifacts",
        added=added,
        removed=removed,
        modified=modified,
    )


def _diff_custody_events(a_events: list[EventRecord], b_events: list[EventRecord]) -> DiffGroup:
    hashes_a = {ev.event_hash: ev for ev in a_events}
    hashes_b = {ev.event_hash: ev for ev in b_events}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []

    for h in sorted(hashes_b.keys() - hashes_a.keys()):
        ev = hashes_b[h]
        added.append(
            {
                "event_hash": ev.event_hash,
                "event_type": ev.event_type,
                "aggregate_type": ev.aggregate_type,
                "aggregate_id": ev.aggregate_id,
                "timestamp_utc": ev.timestamp_utc,
                "actor": ev.actor,
            }
        )

    for h in sorted(hashes_a.keys() - hashes_b.keys()):
        ev = hashes_a[h]
        removed.append(
            {
                "event_hash": ev.event_hash,
                "event_type": ev.event_type,
                "aggregate_type": ev.aggregate_type,
                "aggregate_id": ev.aggregate_id,
                "timestamp_utc": ev.timestamp_utc,
                "actor": ev.actor,
            }
        )

    return DiffGroup(
        section="custody",
        added=added,
        removed=removed,
        modified=modified,
    )


def diff_cases(
    case_dir_a: pathlib.Path,
    case_dir_b: pathlib.Path,
) -> CaseDiffResult:
    manifest_a = load_case_manifest(case_dir_a)
    manifest_b = load_case_manifest(case_dir_b)

    store_a = CaseStore.open(case_dir_a)
    store_b = CaseStore.open(case_dir_b)
    events_a = store_a.event_chain()
    events_b = store_b.event_chain()

    manifest_diff = _diff_manifest_fields(manifest_a, manifest_b)
    artifacts_diff = _diff_artifacts(manifest_a, manifest_b)
    custody_diff = _diff_custody_events(events_a, events_b)

    summary = {
        "manifest_added": len(manifest_diff.added),
        "manifest_removed": len(manifest_diff.removed),
        "manifest_modified": len(manifest_diff.modified),
        "artifacts_added": len(artifacts_diff.added),
        "artifacts_removed": len(artifacts_diff.removed),
        "artifacts_modified": len(artifacts_diff.modified),
        "custody_added": len(custody_diff.added),
        "custody_removed": len(custody_diff.removed),
        "custody_modified": len(custody_diff.modified),
    }

    return CaseDiffResult(
        case_a=str(case_dir_a),
        case_b=str(case_dir_b),
        manifest_diff=manifest_diff,
        artifacts_diff=artifacts_diff,
        custody_diff=custody_diff,
        summary=summary,
    )


def format_unified_diff(result: CaseDiffResult) -> str:
    lines: list[str] = []
    lines.append(f"--- {result.case_a}")
    lines.append(f"+++ {result.case_b}")

    lines.append("")
    lines.append("@@ manifest @@")
    for item in result.manifest_diff.added:
        lines.append(f"+ {item['field']}: {item['value']}")
    for item in result.manifest_diff.removed:
        lines.append(f"- {item['field']}: {item['value']}")
    for item in result.manifest_diff.modified:
        lines.append(f"- {item['field']}: {item['old_value']}")
        lines.append(f"+ {item['field']}: {item['new_value']}")

    lines.append("")
    lines.append("@@ artifacts @@")
    for item in result.artifacts_diff.added:
        lines.append(
            f"+ artifact {item['artifact_id']} | {item['path']} | sha256={item['sha256']} | size={item['size_bytes']}"
        )
    for item in result.artifacts_diff.removed:
        lines.append(
            f"- artifact {item['artifact_id']} | {item['path']} | sha256={item['sha256']} | size={item['size_bytes']}"
        )
    for item in result.artifacts_diff.modified:
        lines.append(f"* artifact {item['artifact_id']}:")
        for change in item["changes"]:
            lines.append(f"  - {change['field']}: {change['old_value']}")
            lines.append(f"  + {change['field']}: {change['new_value']}")

    lines.append("")
    lines.append("@@ custody events @@")
    for item in result.custody_diff.added:
        lines.append(
            f"+ {item['event_hash'][:12]}… | {item['event_type']} | {item['aggregate_id']} | {item['timestamp_utc']}"
        )
    for item in result.custody_diff.removed:
        lines.append(
            f"- {item['event_hash'][:12]}… | {item['event_type']} | {item['aggregate_id']} | {item['timestamp_utc']}"
        )

    return "\n".join(lines)


def diff_result_to_dict(result: CaseDiffResult) -> dict[str, Any]:
    return {
        "case_a": result.case_a,
        "case_b": result.case_b,
        "summary": result.summary,
        "manifest": {
            "added": result.manifest_diff.added,
            "removed": result.manifest_diff.removed,
            "modified": result.manifest_diff.modified,
        },
        "artifacts": {
            "added": result.artifacts_diff.added,
            "removed": result.artifacts_diff.removed,
            "modified": result.artifacts_diff.modified,
        },
        "custody": {
            "added": result.custody_diff.added,
            "removed": result.custody_diff.removed,
            "modified": result.custody_diff.modified,
        },
    }
