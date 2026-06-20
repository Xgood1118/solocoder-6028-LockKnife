from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import tempfile
import threading
from typing import Any

_LOCK = threading.Lock()


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _allowlist_path(case_dir: pathlib.Path) -> pathlib.Path:
    return case_dir / "ioc_allowlist.json"


def load_ioc_allowlist(case_dir: pathlib.Path) -> list[dict[str, Any]]:
    path = _allowlist_path(case_dir)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _save_ioc_allowlist_atomic(
    case_dir: pathlib.Path, entries: list[dict[str, Any]]
) -> pathlib.Path:
    path = _allowlist_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path_str = tempfile.mkstemp(
        prefix=".ioc_allowlist_",
        suffix=".tmp",
        dir=str(case_dir),
    )
    tmp_path = pathlib.Path(tmp_path_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)
        return path
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def add_ioc_to_allowlist(
    case_dir: pathlib.Path,
    ioc: str,
    *,
    reason: str = "",
    source: str = "",
    added_by: str = "system",
    expiry: str | None = None,
) -> dict[str, Any]:
    with _LOCK:
        entries = load_ioc_allowlist(case_dir)
        ioc_lower = ioc.strip().lower()

        for entry in entries:
            if entry.get("ioc", "").lower() == ioc_lower:
                entry["reason"] = reason or entry.get("reason", "")
                entry["source"] = source or entry.get("source", "")
                entry["added_by"] = added_by
                entry["updated_at_utc"] = _utc_now()
                if expiry is not None:
                    entry["expiry"] = expiry
                _save_ioc_allowlist_atomic(case_dir, entries)
                return entry

        entry = {
            "ioc": ioc.strip(),
            "reason": reason,
            "source": source,
            "added_by": added_by,
            "added_at_utc": _utc_now(),
            "updated_at_utc": _utc_now(),
            "expiry": expiry,
        }
        entries.append(entry)
        _save_ioc_allowlist_atomic(case_dir, entries)
        return entry


def remove_ioc_from_allowlist(case_dir: pathlib.Path, ioc: str) -> bool:
    with _LOCK:
        entries = load_ioc_allowlist(case_dir)
        ioc_lower = ioc.strip().lower()
        new_entries = [e for e in entries if e.get("ioc", "").lower() != ioc_lower]
        if len(new_entries) == len(entries):
            return False
        _save_ioc_allowlist_atomic(case_dir, new_entries)
        return True


def is_ioc_allowed(
    case_dir: pathlib.Path,
    ioc: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any] | None:
    entries = load_ioc_allowlist(case_dir)
    ioc_lower = ioc.strip().lower()
    now = now or dt.datetime.now(dt.UTC)

    for entry in entries:
        if entry.get("ioc", "").lower() == ioc_lower:
            expiry_str = entry.get("expiry")
            if expiry_str:
                try:
                    expiry = dt.datetime.fromisoformat(expiry_str)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=dt.UTC)
                    if now > expiry:
                        return None
                except (ValueError, TypeError):
                    pass
            return entry
    return None


def batch_check_allowlist(
    case_dir: pathlib.Path,
    iocs: list[str],
    *,
    now: dt.datetime | None = None,
) -> dict[str, dict[str, Any] | None]:
    entries = load_ioc_allowlist(case_dir)
    by_ioc = {e.get("ioc", "").lower(): e for e in entries}
    now = now or dt.datetime.now(dt.UTC)
    result: dict[str, dict[str, Any] | None] = {}

    for ioc in iocs:
        ioc_lower = ioc.strip().lower()
        entry = by_ioc.get(ioc_lower)
        if entry is None:
            result[ioc] = None
            continue
        expiry_str = entry.get("expiry")
        if expiry_str:
            try:
                expiry = dt.datetime.fromisoformat(expiry_str)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=dt.UTC)
                if now > expiry:
                    result[ioc] = None
                    continue
            except (ValueError, TypeError):
                pass
        result[ioc] = entry

    return result


def record_whitelist_hit_event(
    case_dir: pathlib.Path,
    *,
    ioc: str,
    ioc_kind: str,
    source_command: str,
    artifact_id: str | None = None,
    allowlist_entry: dict[str, Any] | None = None,
    actor: str = "system",
) -> None:
    from lockknife.core._case_store import CaseStore

    store = CaseStore.open(case_dir)
    payload = {
        "ioc": ioc,
        "ioc_kind": ioc_kind,
        "source_command": source_command,
        "artifact_id": artifact_id,
        "allowlist_entry": allowlist_entry or {},
    }
    store.append_event(
        aggregate_type="ioc",
        aggregate_id=ioc,
        event_type="ioc.whitelist_hit",
        payload=payload,
        actor=actor,
    )
    store.write_manifest_snapshot()
