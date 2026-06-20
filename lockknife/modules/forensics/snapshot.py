from __future__ import annotations

import hashlib
import json
import pathlib
import shlex
import tarfile
import time
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.progress import ProgressCallback, emit_progress
from lockknife.core.security import generate_aes256gcm_key, secure_temp_dir


def _validate_snapshot_path(path: str) -> str:
    value = path.strip()
    if not value:
        raise DeviceError("Snapshot paths must be non-empty")
    if any(ch in value for ch in ("\x00", "\n", "\r")):
        raise DeviceError("Snapshot paths contain unsafe control characters")
    if value.startswith("-"):
        raise DeviceError("Snapshot paths cannot start with '-'")
    pure = pathlib.PurePosixPath(value)
    if not pure.is_absolute():
        raise DeviceError("Snapshot paths must be absolute device paths")
    if ".." in pure.parts:
        raise DeviceError("Snapshot paths cannot contain '..'")
    return value


def create_snapshot(
    devices: DeviceManager,
    serial: str,
    *,
    output_path: pathlib.Path,
    paths: list[str] | None = None,
    full: bool = False,
    encrypt: bool = False,
    generate_files_manifest: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> pathlib.Path:
    if not devices.has_root(serial):
        raise DeviceError("Root required to create device snapshot")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with secure_temp_dir(prefix="lockknife-snapshot-") as d:
        remote_tar = "/sdcard/lockknife-snapshot.tar"
        selected = paths or []
        if full:
            selected = ["/data/system", "/data/data"]
        if not selected:
            raise DeviceError("No paths selected for snapshot")

        validated = [_validate_snapshot_path(p) for p in selected]
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="validate",
            message="Validated snapshot inputs",
            current=1,
            total=5,
            metadata={"path_count": len(validated), "encrypted": encrypt},
        )
        joined = " ".join(shlex.quote(p) for p in validated)
        cmd = f'su -c "tar -cf {shlex.quote(remote_tar)} -- {joined} 2>/dev/null"'
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="device-archive",
            message="Creating device-side snapshot archive",
            current=2,
            total=5,
            metadata={"remote_path": remote_tar},
        )
        devices.shell(serial, cmd, timeout_s=600.0)

        local_tar = d / "snapshot.tar"
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="pull",
            message="Pulling snapshot archive from device",
            current=3,
            total=5,
            metadata={"remote_path": remote_tar, "output_path": str(output_path)},
        )
        devices.pull(serial, remote_tar, local_tar, timeout_s=600.0)
        try:
            emit_progress(
                progress_callback,
                operation="forensics.snapshot",
                step="cleanup",
                message="Removing temporary snapshot archive from device",
                current=4,
                total=5,
                metadata={"remote_path": remote_tar},
            )
            devices.shell(serial, f'su -c "rm -f {shlex.quote(remote_tar)}"', timeout_s=30.0)
        except DeviceError:
            pass

        meta = {
            "serial": serial,
            "created_at": time.time(),
            "full": full,
            "paths": validated,
            "encrypted": encrypt,
        }
        meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

        files_manifest: dict[str, dict[str, Any]] = {}
        if generate_files_manifest:
            raw_hashes = _sha256_tar_contents(local_tar)
            files_manifest = {
                path: {**info, "status": "baseline"}
                for path, info in raw_hashes.items()
            }

        if not encrypt:
            output_path.write_bytes(local_tar.read_bytes())
            if generate_files_manifest:
                manifest_path = output_path.with_suffix(output_path.suffix + ".files_manifest.json")
                _write_snapshot_manifest(
                    manifest_path,
                    serial=serial,
                    created_at=meta["created_at"],
                    full=full,
                    paths=validated,
                    encrypted=False,
                    files=files_manifest,
                )
            emit_progress(
                progress_callback,
                operation="forensics.snapshot",
                step="complete",
                message="Snapshot completed",
                current=5,
                total=5,
                metadata={"output_path": str(output_path), "file_count": len(files_manifest)},
            )
            return output_path

        from lockknife.core.security import encrypt_file

        key = generate_aes256gcm_key()
        key_path = output_path.with_suffix(output_path.suffix + ".key")
        key_path.write_bytes(key)
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="encrypt",
            message="Encrypting snapshot archive",
            current=5,
            total=5,
            metadata={"output_path": str(output_path)},
        )
        encrypted_path = encrypt_file(
            local_tar, key, out_path=output_path.with_suffix(output_path.suffix + ".lkenc")
        )
        if generate_files_manifest:
            manifest_path = output_path.with_suffix(output_path.suffix + ".files_manifest.json")
            _write_snapshot_manifest(
                manifest_path,
                serial=serial,
                created_at=meta["created_at"],
                full=full,
                paths=validated,
                encrypted=True,
                files=files_manifest,
            )
        return encrypted_path


def _list_device_files(
    devices: DeviceManager,
    serial: str,
    paths: list[str],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for base_path in paths:
        cmd = f'su -c "find {shlex.quote(base_path)} -type f -exec stat -c \'%n|%s|%Y\' {{}} \\; 2>/dev/null"'
        output = devices.shell(serial, cmd, timeout_s=300.0)
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|", 2)
            if len(parts) == 3:
                filepath, size_str, mtime_str = parts
                try:
                    results.append(
                        {
                            "path": filepath.strip(),
                            "size_bytes": int(size_str.strip()),
                            "mtime": int(mtime_str.strip()),
                        }
                    )
                except ValueError:
                    continue
    return results


def _sha256_tar_contents(tar_path: pathlib.Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with tarfile.open(tar_path, "r") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            h = hashlib.sha256()
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
            result[member.name] = {
                "path": member.name,
                "size_bytes": member.size,
                "mtime": member.mtime,
                "sha256": h.hexdigest(),
            }
    return result


def _write_snapshot_manifest(
    manifest_path: pathlib.Path,
    *,
    serial: str,
    created_at: float,
    full: bool,
    paths: list[str],
    encrypted: bool,
    files: dict[str, dict[str, Any]],
    parent_snapshot_artifact_id: str | None = None,
    base_artifact_id: str | None = None,
) -> None:
    manifest = {
        "schema_version": 1,
        "serial": serial,
        "created_at": created_at,
        "full": full,
        "paths": paths,
        "encrypted": encrypted,
        "parent_snapshot_artifact_id": parent_snapshot_artifact_id,
        "base_artifact_id": base_artifact_id,
        "file_count": len(files),
        "files": files,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _extract_base_artifact_id(
    previous_manifest: dict[str, Any] | None,
    parent_snapshot_artifact_id: str | None,
) -> str | None:
    if previous_manifest is not None:
        base_id = previous_manifest.get("base_artifact_id")
        if base_id:
            return base_id
        parent_id = previous_manifest.get("parent_snapshot_artifact_id")
        if parent_id:
            return parent_id
    return parent_snapshot_artifact_id


def load_snapshot_manifest(manifest_path: pathlib.Path) -> dict[str, Any]:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def create_incremental_snapshot(
    devices: DeviceManager,
    serial: str,
    *,
    output_path: pathlib.Path,
    paths: list[str] | None = None,
    full: bool = False,
    encrypt: bool = False,
    previous_manifest_path: pathlib.Path | None = None,
    parent_snapshot_artifact_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    if not devices.has_root(serial):
        raise DeviceError("Root required to create device snapshot")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected = paths or []
    if full:
        selected = ["/data/system", "/data/data"]
    if not selected:
        raise DeviceError("No paths selected for snapshot")

    validated = [_validate_snapshot_path(p) for p in selected]
    total_steps = 7

    emit_progress(
        progress_callback,
        operation="forensics.incremental_snapshot",
        step="validate",
        message="Validated snapshot inputs",
        current=1,
        total=total_steps,
        metadata={"path_count": len(validated), "encrypted": encrypt},
    )

    previous_files: dict[str, dict[str, Any]] = {}
    previous_manifest_data: dict[str, Any] | None = None
    if previous_manifest_path is not None and previous_manifest_path.exists():
        previous_manifest_data = load_snapshot_manifest(previous_manifest_path)
        previous_files = previous_manifest_data.get("files", {})

    base_artifact_id = _extract_base_artifact_id(previous_manifest_data, parent_snapshot_artifact_id)

    emit_progress(
        progress_callback,
        operation="forensics.incremental_snapshot",
        step="scan",
        message="Scanning device files for changes",
        current=2,
        total=total_steps,
        metadata={"previous_file_count": len(previous_files)},
    )
    current_files_meta = _list_device_files(devices, serial, validated)

    need_hash_paths: list[str] = []
    definitely_changed_paths: list[str] = []
    unchanged_files: dict[str, dict[str, Any]] = {}

    current_meta_by_path = {f["path"]: f for f in current_files_meta}
    previous_by_path = {k: v for k, v in previous_files.items()}

    for filepath, meta in current_meta_by_path.items():
        prev = previous_by_path.get(filepath)
        if prev is None:
            definitely_changed_paths.append(filepath)
        elif (
            prev.get("size_bytes") != meta["size_bytes"]
            or prev.get("mtime") != meta["mtime"]
        ):
            definitely_changed_paths.append(filepath)
        else:
            need_hash_paths.append(filepath)

    emit_progress(
        progress_callback,
        operation="forensics.incremental_snapshot",
        step="sha256-verify",
        message="Verifying SHA-256 for mtime/size-matched files",
        current=3,
        total=total_steps,
        metadata={"verify_count": len(need_hash_paths)},
    )

    hash_verified_files: dict[str, dict[str, Any]] = {}
    if need_hash_paths:
        with secure_temp_dir(prefix="lockknife-hash-verify-") as hash_temp_dir:
            verify_remote_tar = "/sdcard/lockknife-hash-verify.tar"
            joined = " ".join(shlex.quote(p) for p in need_hash_paths)
            cmd = f'su -c "tar -cf {shlex.quote(verify_remote_tar)} -- {joined} 2>/dev/null"'
            devices.shell(serial, cmd, timeout_s=600.0)

            local_verify_tar = hash_temp_dir / "verify.tar"
            devices.pull(serial, verify_remote_tar, local_verify_tar, timeout_s=600.0)
            try:
                devices.shell(serial, f'su -c "rm -f {shlex.quote(verify_remote_tar)}"', timeout_s=30.0)
            except DeviceError:
                pass

            verify_hashes = _sha256_tar_contents(local_verify_tar)

        for filepath in need_hash_paths:
            prev = previous_by_path.get(filepath)
            new_hash_info = verify_hashes.get(filepath)
            if new_hash_info is None:
                definitely_changed_paths.append(filepath)
                continue
            prev_sha256 = prev.get("sha256", "") if prev else ""
            if prev_sha256 and new_hash_info.get("sha256") == prev_sha256:
                unchanged_files[filepath] = {
                    "path": filepath,
                    "size_bytes": new_hash_info["size_bytes"],
                    "mtime": new_hash_info["mtime"],
                    "sha256": new_hash_info["sha256"],
                    "status": "unchanged",
                    "previous_artifact_id": parent_snapshot_artifact_id,
                    "base_artifact_id": base_artifact_id,
                }
            else:
                definitely_changed_paths.append(filepath)
                hash_verified_files[filepath] = new_hash_info

    all_changed_paths = definitely_changed_paths

    emit_progress(
        progress_callback,
        operation="forensics.incremental_snapshot",
        step="device-archive",
        message="Creating device-side snapshot of changed files",
        current=4,
        total=total_steps,
        metadata={"changed_count": len(all_changed_paths)},
    )

    with secure_temp_dir(prefix="lockknife-snapshot-") as d:
        remote_tar = "/sdcard/lockknife-snapshot.tar"
        if all_changed_paths:
            joined = " ".join(shlex.quote(p) for p in all_changed_paths)
            cmd = f'su -c "tar -cf {shlex.quote(remote_tar)} -- {joined} 2>/dev/null"'
            devices.shell(serial, cmd, timeout_s=600.0)
        else:
            devices.shell(serial, f'su -c "tar -cf {shlex.quote(remote_tar)} --files-from /dev/null 2>/dev/null"', timeout_s=30.0)

        local_tar = d / "snapshot.tar"
        emit_progress(
            progress_callback,
            operation="forensics.incremental_snapshot",
            step="pull",
            message="Pulling snapshot archive from device",
            current=5,
            total=total_steps,
            metadata={"remote_path": remote_tar, "output_path": str(output_path)},
        )
        devices.pull(serial, remote_tar, local_tar, timeout_s=600.0)
        try:
            emit_progress(
                progress_callback,
                operation="forensics.incremental_snapshot",
                step="cleanup",
                message="Removing temporary snapshot archive from device",
                current=6,
                total=total_steps,
                metadata={"remote_path": remote_tar},
            )
            devices.shell(serial, f'su -c "rm -f {shlex.quote(remote_tar)}"', timeout_s=30.0)
        except DeviceError:
            pass

        changed_files_hashes = _sha256_tar_contents(local_tar)
        for filepath, info in hash_verified_files.items():
            if filepath not in changed_files_hashes:
                changed_files_hashes[filepath] = info

        all_files: dict[str, dict[str, Any]] = {}
        for filepath, info in unchanged_files.items():
            all_files[filepath] = info
        for filepath, info in changed_files_hashes.items():
            all_files[filepath] = {
                **info,
                "status": "changed",
                "base_artifact_id": base_artifact_id,
            }

        final_output = output_path
        if encrypt:
            from lockknife.core.security import encrypt_file

            key = generate_aes256gcm_key()
            key_path = output_path.with_suffix(output_path.suffix + ".key")
            key_path.write_bytes(key)
            final_output = encrypt_file(
                local_tar, key, out_path=output_path.with_suffix(output_path.suffix + ".lkenc")
            )
        else:
            output_path.write_bytes(local_tar.read_bytes())

        created_at = time.time()
        meta = {
            "serial": serial,
            "created_at": created_at,
            "full": full,
            "paths": validated,
            "encrypted": encrypt,
            "incremental": True,
            "changed_file_count": len(changed_files_hashes),
            "unchanged_file_count": len(unchanged_files),
            "total_file_count": len(all_files),
            "parent_snapshot_artifact_id": parent_snapshot_artifact_id,
            "base_artifact_id": base_artifact_id,
        }
        meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

        manifest_path = output_path.with_suffix(output_path.suffix + ".files_manifest.json")
        _write_snapshot_manifest(
            manifest_path,
            serial=serial,
            created_at=created_at,
            full=full,
            paths=validated,
            encrypted=encrypt,
            files=all_files,
            parent_snapshot_artifact_id=parent_snapshot_artifact_id,
            base_artifact_id=base_artifact_id,
        )

        emit_progress(
            progress_callback,
            operation="forensics.incremental_snapshot",
            step="complete",
            message="Incremental snapshot completed",
            current=7,
            total=total_steps,
            metadata={
                "output_path": str(final_output),
                "changed_count": len(changed_files_hashes),
                "unchanged_count": len(unchanged_files),
                "verified_sha256_count": len(need_hash_paths),
                "base_artifact_id": base_artifact_id,
            },
        )

        return {
            "output_path": final_output,
            "meta_path": meta_path,
            "manifest_path": manifest_path,
            "key_path": output_path.with_suffix(output_path.suffix + ".key") if encrypt else None,
            "changed_file_count": len(changed_files_hashes),
            "unchanged_file_count": len(unchanged_files),
            "total_file_count": len(all_files),
            "files": all_files,
            "encrypted": encrypt,
            "parent_snapshot_artifact_id": parent_snapshot_artifact_id,
            "base_artifact_id": base_artifact_id,
        }
