#!/usr/bin/env python3
"""Sync Antigravity conversation history into Antigravity IDE on Linux.

The Linux 2.x IDE keeps conversation payloads under ``~/.gemini`` and the
sidebar index under ``state.vscdb``. Copying only ``*.pb`` / ``*.db`` files
is not enough: the sidebar also needs updated trajectory summaries and
workspace metadata. This script performs the full migration non-destructively.

It also writes an audit report named ``projects.json``. That report is for
verification; the IDE itself still reads ``workspaceStorage/workspace.json``
and ``state.vscdb``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence
from urllib.parse import quote, unquote


SYNC_DIRS = ("conversations", "brain", "implicit", "knowledge", "context_state")
CONVERSATION_SUFFIXES = (".pb", ".db")
STATE_KEY = "antigravityUnifiedStateSync.trajectorySummaries"
DEFAULT_SOURCE_GEMINI = "~/.gemini/antigravity"
DEFAULT_TARGET_GEMINI = "~/.gemini/antigravity-ide"
DEFAULT_SOURCE_CONFIG = "~/.config/Antigravity"
DEFAULT_TARGET_CONFIG = "~/.config/Antigravity IDE"
GENERIC_URI_RE = re.compile(r"(?:vscode-remote://[^\s\"'<>]+|file:///[^\"'<>]+)")
GENERIC_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._ %:+@=-]+){2,}")


@dataclass(frozen=True)
class WorkspaceRecord:
    storage_id: str
    uri: str
    local_path: str | None
    source_file: Path
    fingerprints: tuple[str, ...]


@dataclass
class CopyRecord:
    relative_path: str
    src: str
    dst: str
    size: int
    sha256: str
    action: str


@dataclass
class ConversationRecord:
    conversation_id: str
    format: str
    path: Path
    title: str
    title_source: str
    workspace_uri: str | None = None
    workspace_storage_id: str | None = None
    workspace_path: str | None = None
    workspace_source: str | None = None
    evidence: list[dict[str, str]] = field(default_factory=list)
    existing_inner_blob: bytes | None = None


@dataclass
class ExistingMetadata:
    titles: dict[str, str]
    inner_blobs: dict[str, bytes]


@dataclass
class Paths:
    source_gemini_root: Path
    target_gemini_root: Path
    source_config_root: Path
    target_config_root: Path
    backup_root: Path
    projects_report: Path
    source_workspace_storage: Path
    target_workspace_storage: Path
    source_state_db: Path
    target_state_db: Path


def info(message: str) -> None:
    print(f"[INFO] {message}")


def ok(message: str) -> None:
    print(f"[ OK ] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def fail(message: str) -> "NoReturn":
    print(f"[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


def expand_path(raw: str) -> Path:
    return Path(os.path.expanduser(raw)).resolve()


def timestamp_slug() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identical_files(src: Path, dst: Path) -> bool:
    if not dst.exists() or src.stat().st_size != dst.stat().st_size:
        return False
    return sha256_file(src) == sha256_file(dst)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def backup_if_needed(src_root: Path, dst_file: Path, backup_root: Path, dry_run: bool) -> None:
    if not dst_file.exists():
        return
    relative = dst_file.relative_to(src_root)
    backup_file = backup_root / relative
    if backup_file.exists():
        return
    info(f"Backing up {dst_file} -> {backup_file}")
    if dry_run:
        return
    ensure_parent(backup_file)
    shutil.copy2(dst_file, backup_file)


def is_antigravity_running() -> bool:
    try:
        completed = subprocess.run(
            ["pgrep", "-af", "antigravity"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return bool(completed.stdout.strip())


def sync_directory(
    src_root: Path,
    dst_root: Path,
    backup_root: Path,
    dry_run: bool,
) -> list[CopyRecord]:
    results: list[CopyRecord] = []
    if not src_root.exists():
        warn(f"Skipping missing source directory: {src_root}")
        return results

    for src_file in sorted(path for path in src_root.rglob("*") if path.is_file()):
        relative = src_file.relative_to(src_root)
        dst_file = dst_root / relative
        action = "unchanged"

        if not dst_file.exists():
            action = "copied"
        elif not identical_files(src_file, dst_file):
            action = "updated"
        else:
            results.append(
                CopyRecord(
                    relative_path=relative.as_posix(),
                    src=str(src_file),
                    dst=str(dst_file),
                    size=src_file.stat().st_size,
                    sha256=sha256_file(src_file),
                    action=action,
                )
            )
            continue

        if action == "updated":
            backup_if_needed(dst_root, dst_file, backup_root, dry_run)

        info(f"{action.capitalize()} {src_file} -> {dst_file}")
        if not dry_run:
            ensure_parent(dst_file)
            shutil.copy2(src_file, dst_file)

        results.append(
            CopyRecord(
                relative_path=relative.as_posix(),
                src=str(src_file),
                dst=str(dst_file),
                size=src_file.stat().st_size,
                sha256=sha256_file(src_file),
                action=action,
            )
        )
    return results


def load_workspaces(*workspace_roots: Path) -> list[WorkspaceRecord]:
    records: dict[str, WorkspaceRecord] = {}

    for workspace_root in workspace_roots:
        if not workspace_root.exists():
            continue
        for workspace_json in sorted(workspace_root.glob("*/workspace.json")):
            try:
                payload = json.loads(workspace_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                warn(f"Unable to read {workspace_json}: {exc}")
                continue

            uri = payload.get("folder") or payload.get("workspace")
            if not isinstance(uri, str) or not uri:
                continue

            local_path = uri_to_local_path(uri)
            storage_id = workspace_json.parent.name
            record = WorkspaceRecord(
                storage_id=storage_id,
                uri=uri,
                local_path=local_path,
                source_file=workspace_json,
                fingerprints=build_workspace_fingerprints(uri, local_path),
            )
            records.setdefault(uri, record)

    sorted_records = sorted(
        records.values(),
        key=lambda item: max(len(item.uri), len(item.local_path or "")),
        reverse=True,
    )
    return sorted_records


def uri_to_local_path(uri: str) -> str | None:
    if uri.startswith("file:///"):
        path = unquote(uri[len("file://"):])
        return path if path.startswith("/") else f"/{path}"
    return None


def local_path_to_file_uri(path: str) -> str:
    return "file://" + quote(path)


def build_workspace_fingerprints(uri: str, local_path: str | None) -> tuple[str, ...]:
    candidates = {uri, unquote(uri)}
    if local_path:
        normalized = local_path.replace("\\", "/")
        candidates.add(local_path)
        candidates.add(normalized)
        candidates.add(local_path_to_file_uri(local_path))
        candidates.add(local_path_to_file_uri(normalized))
    return tuple(sorted(candidate for candidate in candidates if candidate))


def collect_conversations(conversations_dir: Path) -> dict[str, Path]:
    records: dict[str, Path] = {}
    if not conversations_dir.exists():
        return records

    for file_path in sorted(conversations_dir.iterdir()):
        if not file_path.is_file():
            continue
        if file_path.name.endswith((".db-wal", ".db-shm")):
            continue
        if file_path.suffix not in CONVERSATION_SUFFIXES:
            continue
        records[file_path.stem] = file_path
    return records


def related_paths(gemini_root: Path, conversation_id: str) -> list[Path]:
    results: list[Path] = []
    for folder_name in SYNC_DIRS[1:]:
        folder = gemini_root / folder_name / conversation_id
        if folder.is_dir():
            results.extend(sorted(path for path in folder.rglob("*") if path.is_file()))
        elif folder.is_file():
            results.append(folder)
        for sibling in sorted((gemini_root / folder_name).glob(f"{conversation_id}*")):
            if sibling.is_file():
                results.append(sibling)
    return results


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def text_from_bytes(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def count_workspace_hits(data: bytes, workspaces: Sequence[WorkspaceRecord]) -> dict[str, int]:
    scores: dict[str, int] = {}
    for workspace in workspaces:
        score = 0
        for fingerprint in workspace.fingerprints:
            encoded = fingerprint.encode("utf-8", errors="ignore")
            if not encoded:
                continue
            hit_count = data.count(encoded)
            if hit_count:
                score += hit_count * max(1, len(encoded) // 24)
        if score:
            scores[workspace.uri] = scores.get(workspace.uri, 0) + score
    return scores


def merge_scores(base: dict[str, int], updates: dict[str, int]) -> None:
    for uri, score in updates.items():
        base[uri] = base.get(uri, 0) + score


def choose_workspace(scores: dict[str, int], workspaces: Sequence[WorkspaceRecord]) -> WorkspaceRecord | None:
    if not scores:
        return None
    by_uri = {record.uri: record for record in workspaces}
    return max(
        (by_uri[uri] for uri in scores),
        key=lambda record: (scores[record.uri], len(record.local_path or ""), len(record.uri)),
    )


def extract_generic_candidates(text: str) -> list[str]:
    matches = set(GENERIC_URI_RE.findall(text))
    for candidate in GENERIC_PATH_RE.findall(text):
        cleaned = candidate.rstrip(").,;]")
        if cleaned.count("/") >= 2:
            matches.add(cleaned)
    return sorted(matches, key=len, reverse=True)


def map_generic_candidate(candidate: str, workspaces: Sequence[WorkspaceRecord]) -> WorkspaceRecord | None:
    normalized_path = uri_to_local_path(candidate) if candidate.startswith("file:///") else candidate
    normalized_path = normalized_path.replace("\\", "/") if normalized_path else None
    normalized_uri = candidate if candidate.startswith("vscode-remote://") else None

    for workspace in workspaces:
        if normalized_uri:
            if candidate == workspace.uri or candidate.startswith(workspace.uri.rstrip("/") + "/"):
                return workspace
            continue

        if normalized_path and workspace.local_path:
            workspace_path = workspace.local_path.replace("\\", "/")
            if normalized_path == workspace_path or normalized_path.startswith(workspace_path.rstrip("/") + "/"):
                return workspace
    return None


def scan_sqlite_payloads(path: Path) -> Iterator[tuple[str, bytes]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        tables = [
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        for table_name in tables:
            quoted = '"' + table_name.replace('"', '""') + '"'
            columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({quoted})")]
            cursor = connection.execute(f"SELECT * FROM {quoted}")
            for row in cursor:
                for column in columns:
                    value = row[column]
                    if isinstance(value, str):
                        yield (f"{table_name}.{column}", value.encode("utf-8", errors="ignore"))
                    elif isinstance(value, (bytes, bytearray, memoryview)):
                        yield (f"{table_name}.{column}", bytes(value))
    finally:
        connection.close()


def get_title_from_brain(gemini_root: Path, conversation_id: str) -> str | None:
    brain_dir = gemini_root / "brain" / conversation_id
    if not brain_dir.is_dir():
        return None
    for md_file in sorted(brain_dir.glob("*.md")):
        try:
            first_line = md_file.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
        except (OSError, IndexError):
            continue
        if first_line.startswith("#"):
            return first_line.lstrip("# ").strip()
    return None


def encode_varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result or b"\x00")


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        current = data[pos]
        result |= (current & 0x7F) << shift
        pos += 1
        if current & 0x80 == 0:
            return result, pos
        shift += 7
    return result, pos


def skip_protobuf_field(data: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:
        _, pos = decode_varint(data, pos)
    elif wire_type == 1:
        pos += 8
    elif wire_type == 2:
        length, pos = decode_varint(data, pos)
        pos += length
    elif wire_type == 5:
        pos += 4
    return pos


def strip_field_from_protobuf(data: bytes, target_field_number: int) -> bytes:
    remaining = bytearray()
    pos = 0
    while pos < len(data):
        start = pos
        try:
            tag, pos = decode_varint(data, pos)
        except Exception:
            remaining.extend(data[start:])
            break
        field_number = tag >> 3
        wire_type = tag & 7
        next_pos = skip_protobuf_field(data, pos, wire_type)
        if next_pos == pos and wire_type not in (0, 1, 2, 5):
            remaining.extend(data[start:])
            break
        pos = next_pos
        if field_number != target_field_number:
            remaining.extend(data[start:pos])
    return bytes(remaining)


def encode_length_delimited(field_number: int, payload: bytes) -> bytes:
    return encode_varint((field_number << 3) | 2) + encode_varint(len(payload)) + payload


def encode_string_field(field_number: int, value: str) -> bytes:
    return encode_length_delimited(field_number, value.encode("utf-8"))


def build_workspace_field(workspace_uri: str) -> bytes:
    inner = encode_string_field(1, workspace_uri) + encode_string_field(2, workspace_uri)
    return encode_length_delimited(9, inner)


def build_timestamp_fields(epoch_seconds: float) -> bytes:
    ts_inner = encode_varint((1 << 3) | 0) + encode_varint(int(epoch_seconds))
    return (
        encode_length_delimited(3, ts_inner)
        + encode_length_delimited(7, ts_inner)
        + encode_length_delimited(10, ts_inner)
    )


def has_timestamp_fields(inner_blob: bytes) -> bool:
    pos = 0
    while pos < len(inner_blob):
        tag, pos = decode_varint(inner_blob, pos)
        field_number = tag >> 3
        wire_type = tag & 7
        if field_number in (3, 7, 10):
            return True
        pos = skip_protobuf_field(inner_blob, pos, wire_type)
    return False


def extract_workspace_hint(inner_blob: bytes) -> str | None:
    pos = 0
    while pos < len(inner_blob):
        tag, pos = decode_varint(inner_blob, pos)
        field_number = tag >> 3
        wire_type = tag & 7
        if wire_type != 2:
            pos = skip_protobuf_field(inner_blob, pos, wire_type)
            continue
        length, pos = decode_varint(inner_blob, pos)
        content = inner_blob[pos : pos + length]
        pos += length
        if field_number == 9:
            sub_pos = 0
            while sub_pos < len(content):
                sub_tag, sub_pos = decode_varint(content, sub_pos)
                sub_field = sub_tag >> 3
                sub_wire_type = sub_tag & 7
                if sub_wire_type != 2:
                    sub_pos = skip_protobuf_field(content, sub_pos, sub_wire_type)
                    continue
                sub_length, sub_pos = decode_varint(content, sub_pos)
                sub_content = content[sub_pos : sub_pos + sub_length]
                sub_pos += sub_length
                try:
                    text = sub_content.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if sub_field in (1, 2) and ("file:///" in text or "vscode-remote://" in text):
                    return text
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "file:///" in text or "vscode-remote://" in text:
            return text
    return None


def parse_trajectory_summaries(encoded_value: str) -> list[dict[str, str]]:
    decoded = base64.b64decode(encoded_value)
    results: list[dict[str, str]] = []
    pos = 0
    while pos < len(decoded):
        tag, pos = decode_varint(decoded, pos)
        if tag & 7 != 2:
            break
        length, pos = decode_varint(decoded, pos)
        entry = decoded[pos : pos + length]
        pos += length

        entry_pos = 0
        conversation_id = None
        title = None
        workspace = None
        while entry_pos < len(entry):
            inner_tag, entry_pos = decode_varint(entry, entry_pos)
            field_number = inner_tag >> 3
            wire_type = inner_tag & 7
            if field_number == 1 and wire_type == 2:
                length, entry_pos = decode_varint(entry, entry_pos)
                conversation_id = entry[entry_pos : entry_pos + length].decode("utf-8", errors="ignore")
                entry_pos += length
                continue
            if field_number == 2 and wire_type == 2:
                length, entry_pos = decode_varint(entry, entry_pos)
                sub_message = entry[entry_pos : entry_pos + length]
                entry_pos += length
                sub_pos = 0
                while sub_pos < len(sub_message):
                    sub_tag, sub_pos = decode_varint(sub_message, sub_pos)
                    if (sub_tag >> 3) == 1 and (sub_tag & 7) == 2:
                        sub_length, sub_pos = decode_varint(sub_message, sub_pos)
                        payload = sub_message[sub_pos : sub_pos + sub_length]
                        sub_pos += sub_length
                        inner_blob = base64.b64decode(payload)
                        workspace = extract_workspace_hint(inner_blob)
                        try:
                            title_pos = 0
                            title_tag, title_pos = decode_varint(inner_blob, title_pos)
                            if (title_tag >> 3) == 1 and (title_tag & 7) == 2:
                                title_length, title_pos = decode_varint(inner_blob, title_pos)
                                title = inner_blob[title_pos : title_pos + title_length].decode(
                                    "utf-8", errors="ignore"
                                )
                        except Exception:
                            pass
                        break
                    sub_pos = skip_protobuf_field(sub_message, sub_pos, sub_tag & 7)
                continue
            entry_pos = skip_protobuf_field(entry, entry_pos, wire_type)
        if conversation_id:
            results.append(
                {
                    "conversation_id": conversation_id,
                    "title": title or "",
                    "workspace_uri": workspace or "",
                }
            )
    return results


def load_existing_metadata(db_paths: Sequence[Path]) -> ExistingMetadata:
    titles: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    for db_path in db_paths:
        if not db_path.exists():
            continue
        try:
            connection = sqlite3.connect(db_path)
            cursor = connection.cursor()
            cursor.execute("SELECT value FROM ItemTable WHERE key=?", (STATE_KEY,))
            row = cursor.fetchone()
            connection.close()
        except sqlite3.DatabaseError as exc:
            warn(f"Unable to read {db_path}: {exc}")
            continue

        if not row or not row[0]:
            continue

        try:
            decoded = base64.b64decode(row[0])
        except Exception as exc:
            warn(f"Unable to decode trajectory summaries in {db_path}: {exc}")
            continue

        pos = 0
        while pos < len(decoded):
            tag, pos = decode_varint(decoded, pos)
            if tag & 7 != 2:
                break
            length, pos = decode_varint(decoded, pos)
            entry = decoded[pos : pos + length]
            pos += length

            entry_pos = 0
            conversation_id = None
            info_payload = None
            while entry_pos < len(entry):
                inner_tag, entry_pos = decode_varint(entry, entry_pos)
                field_number = inner_tag >> 3
                wire_type = inner_tag & 7
                if wire_type == 2:
                    inner_length, entry_pos = decode_varint(entry, entry_pos)
                    content = entry[entry_pos : entry_pos + inner_length]
                    entry_pos += inner_length
                    if field_number == 1:
                        conversation_id = content.decode("utf-8", errors="ignore")
                    elif field_number == 2:
                        sub_pos = 0
                        sub_tag, sub_pos = decode_varint(content, sub_pos)
                        if (sub_tag >> 3) == 1 and (sub_tag & 7) == 2:
                            sub_length, sub_pos = decode_varint(content, sub_pos)
                            info_payload = content[sub_pos : sub_pos + sub_length].decode("utf-8", errors="ignore")
                else:
                    entry_pos = skip_protobuf_field(entry, entry_pos, wire_type)

            if not conversation_id or not info_payload:
                continue
            try:
                inner_blob = base64.b64decode(info_payload)
            except Exception:
                continue
            if conversation_id not in blobs:
                blobs[conversation_id] = inner_blob
            try:
                title_pos = 0
                title_tag, title_pos = decode_varint(inner_blob, title_pos)
                if (title_tag >> 3) == 1 and (title_tag & 7) == 2:
                    title_length, title_pos = decode_varint(inner_blob, title_pos)
                    title = inner_blob[title_pos : title_pos + title_length].decode("utf-8", errors="ignore")
                    if title and not title.startswith("Conversation "):
                        titles.setdefault(conversation_id, title)
            except Exception:
                continue

    return ExistingMetadata(titles=titles, inner_blobs=blobs)


def choose_title(conversation_id: str, gemini_root: Path, metadata: ExistingMetadata, path: Path) -> tuple[str, str]:
    if conversation_id in metadata.titles:
        return metadata.titles[conversation_id], "existing_index"
    brain_title = get_title_from_brain(gemini_root, conversation_id)
    if brain_title:
        return brain_title, "brain"
    return f"Conversation ({time.strftime('%b %d', time.localtime(path.stat().st_mtime))}) {conversation_id[:8]}", "fallback"


def detect_workspace(
    conversation_path: Path,
    gemini_root: Path,
    workspaces: Sequence[WorkspaceRecord],
    existing_workspace_uri: str | None,
) -> tuple[str | None, str | None, str | None, list[dict[str, str]]]:
    evidence: list[dict[str, str]] = []
    aggregate_scores: dict[str, int] = {}

    if existing_workspace_uri:
        existing_match = map_generic_candidate(existing_workspace_uri, workspaces)
        if existing_match:
            evidence.append(
                {
                    "source": "existing_index",
                    "match": existing_match.uri,
                    "workspace_storage_id": existing_match.storage_id,
                }
            )
            return (
                existing_match.uri,
                existing_match.storage_id,
                existing_match.local_path,
                evidence,
            )

    raw_sources: list[tuple[str, bytes]] = [("conversation", read_bytes(conversation_path))]
    if conversation_path.suffix == ".db":
        try:
            raw_sources.extend(scan_sqlite_payloads(conversation_path))
        except sqlite3.DatabaseError as exc:
            warn(f"Unable to scan SQLite conversation {conversation_path}: {exc}")

    for file_path in related_paths(gemini_root, conversation_path.stem):
        try:
            raw_sources.append((file_path.relative_to(gemini_root).as_posix(), read_bytes(file_path)))
        except OSError as exc:
            warn(f"Unable to read {file_path}: {exc}")

    generic_candidates: list[tuple[str, str]] = []
    for source_name, payload in raw_sources:
        merge_scores(aggregate_scores, count_workspace_hits(payload, workspaces))
        for candidate in extract_generic_candidates(text_from_bytes(payload)):
            generic_candidates.append((source_name, candidate))

    matched_workspace = choose_workspace(aggregate_scores, workspaces)
    if matched_workspace:
        evidence.append(
            {
                "source": "fingerprint",
                "match": matched_workspace.uri,
                "workspace_storage_id": matched_workspace.storage_id,
            }
        )
        return (
            matched_workspace.uri,
            matched_workspace.storage_id,
            matched_workspace.local_path,
            evidence,
        )

    for source_name, candidate in generic_candidates:
        matched_workspace = map_generic_candidate(candidate, workspaces)
        if matched_workspace:
            evidence.append(
                {
                    "source": source_name,
                    "match": candidate,
                    "workspace_storage_id": matched_workspace.storage_id,
                }
            )
            return (
                matched_workspace.uri,
                matched_workspace.storage_id,
                matched_workspace.local_path,
                evidence,
            )

    if generic_candidates:
        evidence.append({"source": generic_candidates[0][0], "match": generic_candidates[0][1]})
        candidate = generic_candidates[0][1]
        if candidate.startswith(("vscode-remote://", "file:///")):
            workspace_uri = candidate
        else:
            workspace_uri = local_path_to_file_uri(candidate)
        workspace_path = uri_to_local_path(candidate) if candidate.startswith("file:///") else candidate
        return workspace_uri, None, workspace_path, evidence

    return None, None, None, evidence


def build_entry(
    conversation_id: str,
    title: str,
    existing_inner_blob: bytes | None,
    workspace_uri: str | None,
    mtime: float,
) -> bytes:
    if existing_inner_blob:
        preserved = strip_field_from_protobuf(existing_inner_blob, 1)
        if workspace_uri:
            preserved = strip_field_from_protobuf(preserved, 9)
        inner_blob = encode_string_field(1, title) + preserved
        if workspace_uri:
            inner_blob += build_workspace_field(workspace_uri)
        if not has_timestamp_fields(existing_inner_blob):
            inner_blob += build_timestamp_fields(mtime)
    else:
        inner_blob = encode_string_field(1, title)
        if workspace_uri:
            inner_blob += build_workspace_field(workspace_uri)
        inner_blob += build_timestamp_fields(mtime)

    info_payload = base64.b64encode(inner_blob).decode("utf-8")
    sub_message = encode_string_field(1, info_payload)
    entry = encode_string_field(1, conversation_id) + encode_length_delimited(2, sub_message)
    return encode_length_delimited(1, entry)


def ensure_state_database(path: Path, dry_run: bool) -> None:
    if path.exists() or dry_run:
        return
    info(f"Creating missing state database at {path}")
    ensure_parent(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)")
        connection.commit()
    finally:
        connection.close()


def write_state_index(
    db_path: Path,
    encoded_value: str,
    backup_root: Path,
    dry_run: bool,
) -> None:
    backup_if_needed(db_path.parent, db_path, backup_root, dry_run)
    if dry_run:
        info(f"Dry run: would update {db_path}")
        return

    ensure_state_database(db_path, dry_run=False)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO ItemTable(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (STATE_KEY, encoded_value),
        )
        connection.commit()
    finally:
        connection.close()


def validate_copy(records: Sequence[CopyRecord], dry_run: bool) -> list[str]:
    issues: list[str] = []
    if dry_run:
        return issues
    for record in records:
        src = Path(record.src)
        dst = Path(record.dst)
        if not dst.exists():
            issues.append(f"Missing copied file: {dst}")
            continue
        if sha256_file(src) != sha256_file(dst):
            issues.append(f"Checksum mismatch for {dst}")
    return issues


def validate_state_database(db_path: Path, expected_count: int, dry_run: bool) -> tuple[list[str], list[dict[str, str]]]:
    issues: list[str] = []
    if dry_run:
        return issues, []
    if not db_path.exists():
        return [f"State database not found: {db_path}"], []

    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        cursor.execute("SELECT value FROM ItemTable WHERE key=?", (STATE_KEY,))
        row = cursor.fetchone()
        connection.close()
    except sqlite3.DatabaseError as exc:
        return [f"Unable to read {db_path}: {exc}"], []

    if not row or not row[0]:
        return [f"Missing {STATE_KEY} in {db_path}"], []

    parsed = parse_trajectory_summaries(row[0])
    if len(parsed) != expected_count:
        issues.append(f"Expected {expected_count} trajectory summaries, found {len(parsed)}")
    return issues, parsed


def write_json(path: Path, payload: object, dry_run: bool) -> None:
    info(f"Writing {path}")
    if dry_run:
        return
    ensure_parent(path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def build_paths(args: argparse.Namespace) -> Paths:
    backup_root = expand_path(args.backup_root) if args.backup_root else expand_path(f"~/.gemini/antigravity-ide-migration-backups/{timestamp_slug()}")
    source_gemini_root = expand_path(args.source_gemini_root)
    target_gemini_root = expand_path(args.target_gemini_root)
    source_config_root = expand_path(args.source_config_root)
    target_config_root = expand_path(args.target_config_root)
    projects_report = backup_root / "reports" / "projects.json"
    return Paths(
        source_gemini_root=source_gemini_root,
        target_gemini_root=target_gemini_root,
        source_config_root=source_config_root,
        target_config_root=target_config_root,
        backup_root=backup_root,
        projects_report=projects_report,
        source_workspace_storage=source_config_root / "User" / "workspaceStorage",
        target_workspace_storage=target_config_root / "User" / "workspaceStorage",
        source_state_db=source_config_root / "User" / "globalStorage" / "state.vscdb",
        target_state_db=target_config_root / "User" / "globalStorage" / "state.vscdb",
    )


def build_conversation_records(
    gemini_root: Path,
    metadata: ExistingMetadata,
    workspaces: Sequence[WorkspaceRecord],
) -> list[ConversationRecord]:
    conversation_dir = gemini_root / "conversations"
    conversations = collect_conversations(conversation_dir)
    if not conversations:
        fail(f"No conversation files found in {conversation_dir}")

    records: list[ConversationRecord] = []
    for conversation_id, path in sorted(
        conversations.items(),
        key=lambda item: item[1].stat().st_mtime,
        reverse=True,
    ):
        title, title_source = choose_title(conversation_id, gemini_root, metadata, path)
        existing_blob = metadata.inner_blobs.get(conversation_id)
        existing_workspace_uri = extract_workspace_hint(existing_blob) if existing_blob else None
        workspace_uri, workspace_storage_id, workspace_path, evidence = detect_workspace(
            path,
            gemini_root,
            workspaces,
            existing_workspace_uri,
        )
        record = ConversationRecord(
            conversation_id=conversation_id,
            format=path.suffix.lstrip("."),
            path=path,
            title=title,
            title_source=title_source,
            workspace_uri=workspace_uri,
            workspace_storage_id=workspace_storage_id,
            workspace_path=workspace_path,
            workspace_source=evidence[0]["source"] if evidence else None,
            evidence=evidence,
            existing_inner_blob=existing_blob,
        )
        records.append(record)
    return records


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-gemini-root", default=DEFAULT_SOURCE_GEMINI)
    parser.add_argument("--target-gemini-root", default=DEFAULT_TARGET_GEMINI)
    parser.add_argument("--source-config-root", default=DEFAULT_SOURCE_CONFIG)
    parser.add_argument("--target-config-root", default=DEFAULT_TARGET_CONFIG)
    parser.add_argument("--backup-root", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-running-ide", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    paths = build_paths(args)

    print()
    print("=" * 72)
    print("Antigravity IDE Linux Conversation Sync")
    print("=" * 72)
    print(f"Source gemini root : {paths.source_gemini_root}")
    print(f"Target gemini root : {paths.target_gemini_root}")
    print(f"Source config root : {paths.source_config_root}")
    print(f"Target config root : {paths.target_config_root}")
    print(f"Backup root        : {paths.backup_root}")
    print(f"Dry run            : {args.dry_run}")
    print()

    if is_antigravity_running() and not args.allow_running_ide:
        fail("Antigravity appears to be running. Close it first or use --allow-running-ide.")

    if not paths.source_gemini_root.exists():
        fail(f"Source gemini root does not exist: {paths.source_gemini_root}")

    all_copy_records: list[CopyRecord] = []

    info("Syncing ~/.gemini directories")
    for folder_name in SYNC_DIRS:
        source_dir = paths.source_gemini_root / folder_name
        target_dir = paths.target_gemini_root / folder_name
        backup_dir = paths.backup_root / "target_gemini"
        copied = sync_directory(source_dir, target_dir, backup_dir, args.dry_run)
        all_copy_records.extend(copied)
        ok(f"{folder_name}: {len(copied)} file(s) inspected")

    info("Syncing workspaceStorage")
    workspace_records = sync_directory(
        paths.source_workspace_storage,
        paths.target_workspace_storage,
        paths.backup_root / "target_workspaceStorage",
        args.dry_run,
    )
    all_copy_records.extend(workspace_records)
    ok(f"workspaceStorage: {len(workspace_records)} file(s) inspected")

    info("Loading workspace mappings")
    known_workspaces = load_workspaces(paths.target_workspace_storage, paths.source_workspace_storage)
    if not known_workspaces:
        warn("No workspace.json files found. Workspace mapping will rely on generic path extraction.")
    else:
        ok(f"Loaded {len(known_workspaces)} workspace mapping(s)")
        for workspace in known_workspaces:
            print(f"      {workspace.storage_id} -> {workspace.uri}")

    info("Reading existing conversation metadata from state.vscdb")
    metadata = load_existing_metadata([paths.target_state_db, paths.source_state_db])
    ok(
        f"Preserved {len(metadata.titles)} title(s) and {len(metadata.inner_blobs)} existing summary blob(s)"
    )

    info("Building conversation mapping")
    conversation_records = build_conversation_records(paths.target_gemini_root, metadata, known_workspaces)
    for record in conversation_records:
        workspace_label = record.workspace_path or record.workspace_uri or "<unmapped>"
        print(
            f"      {record.conversation_id} [{record.format}] -> {workspace_label}"
            f" ({record.title_source})"
        )

    info("Rebuilding trajectory summaries index")
    result_bytes = bytearray()
    for record in conversation_records:
        result_bytes.extend(
            build_entry(
                record.conversation_id,
                record.title,
                record.existing_inner_blob,
                record.workspace_uri,
                record.path.stat().st_mtime,
            )
        )
    encoded_value = base64.b64encode(bytes(result_bytes)).decode("utf-8")
    write_state_index(
        paths.target_state_db,
        encoded_value,
        paths.backup_root / "target_state_db",
        args.dry_run,
    )
    ok(f"Updated {paths.target_state_db}")

    info("Validating copied files and rebuilt index")
    copy_issues = validate_copy(all_copy_records, args.dry_run)
    index_issues, parsed_entries = validate_state_database(
        paths.target_state_db,
        expected_count=len(conversation_records),
        dry_run=args.dry_run,
    )
    validation_issues = copy_issues + index_issues

    report_payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_gemini_root": str(paths.source_gemini_root),
        "target_gemini_root": str(paths.target_gemini_root),
        "source_config_root": str(paths.source_config_root),
        "target_config_root": str(paths.target_config_root),
        "dry_run": args.dry_run,
        "conversations": [
            {
                "conversation_id": record.conversation_id,
                "format": record.format,
                "path": str(record.path),
                "title": record.title,
                "title_source": record.title_source,
                "workspace_uri": record.workspace_uri,
                "workspace_path": record.workspace_path,
                "workspace_storage_id": record.workspace_storage_id,
                "workspace_source": record.workspace_source,
                "evidence": record.evidence,
            }
            for record in conversation_records
        ],
        "copied_files": [record.__dict__ for record in all_copy_records],
        "state_index_preview": parsed_entries,
        "validation_issues": validation_issues,
    }
    write_json(paths.projects_report, report_payload, args.dry_run)
    write_json(paths.backup_root / "reports" / "validation.json", report_payload, args.dry_run)

    if validation_issues:
        warn("Validation completed with issues:")
        for issue in validation_issues:
            print(f"      - {issue}")
        return 2

    ok("Validation passed")
    print()
    print("Next step: start Antigravity IDE and confirm the conversations appear in the sidebar.")
    print(f"Audit report: {paths.projects_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
