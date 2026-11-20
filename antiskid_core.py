
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import socket
import stat as stat_module
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

APP_NAME = "AntiSkid"
APP_VERSION = "0.2.0"

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".pif", ".msi",
    ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".reg", ".sh",
}
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".sh", ".reg",
}
RISKY_DOUBLE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
    ".gif", ".mp3", ".mp4", ".txt", ".rtf",
}
SIGNATURES = (
    (b"MZ", "DOS/Windows PE candidate"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"\x1f\x8b", "GZIP stream"),
    (b"ftyp", "MP4/ISO-BMFF marker"),
)

@dataclass
class Finding:
    severity: str
    title: str
    path: str
    reason: str
    sha256: str = ""
    size: int = 0
    confidence: str = "Heuristic"
    source: str = "File triage"
    observed_at: str = ""

@dataclass
class ForensicEvent:
    timestamp: str
    category: str
    source: str
    title: str
    details: str = ""
    severity: str = "Info"
    record_id: str = ""

@dataclass
class CollectionNote:
    source: str
    status: str
    message: str

@dataclass
class CollectionBundle:
    system_info: dict[str, str] = field(default_factory=dict)
    usb_events: list[ForensicEvent] = field(default_factory=list)
    log_events: list[ForensicEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[CollectionNote] = field(default_factory=list)

    def timeline(self) -> list[ForensicEvent]:
        events = self.usb_events + self.log_events
        for finding in self.findings:
            # Use the observation time captured during collection. Re-reading
            # a file's current mtime later can silently rewrite the timeline.
            events.append(ForensicEvent(
                timestamp=finding.observed_at,
                category="File triage",
                source=finding.source,
                title=finding.title,
                details=f"{finding.path} | {finding.reason}",
                severity=finding.severity,
            ))
        def chronological_key(event: ForensicEvent):
            try:
                stamp = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                return stamp.astimezone(timezone.utc).timestamp()
            except (ValueError, OverflowError):
                return float("-inf")
        return sorted(events, key=chronological_key, reverse=True)

def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts if n)

def sha256_file(
    path: str | os.PathLike[str],
    chunk_size: int = 1024 * 1024,
    expected_stat: os.stat_result | None = None,
) -> str:
    """Hash one regular file and reject a result if it changes while read."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    target = Path(path)
    before_path = target.stat(follow_symlinks=False)
    if stat_module.S_ISLNK(before_path.st_mode) or not stat_module.S_ISREG(before_path.st_mode):
        raise OSError("Refusing to hash a symlink or non-regular file")
    def identity(item: os.stat_result) -> tuple[int, int, int, int]:
        return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if expected_stat is not None and identity(before_path) != identity(expected_stat):
        raise RuntimeError("File changed after metadata sampling; SHA-256 was discarded")

    digest = hashlib.sha256()
    with target.open("rb") as handle:
        before_fd = os.fstat(handle.fileno())
        identity_before = identity(before_fd)
        if identity_before != identity(before_path):
            raise RuntimeError("File changed while opening for hashing; SHA-256 was discarded")
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
        after_fd = os.fstat(handle.fileno())

    after_path = target.stat(follow_symlinks=False)
    identity_after = identity(after_fd)
    path_after = identity(after_path)
    if identity_before != identity_after or identity_after != path_after:
        raise RuntimeError("File changed while hashing; SHA-256 was discarded")
    return digest.hexdigest()

def identify_signature(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "DOS/Windows PE candidate (MZ header; PE signature not yet verified)"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP stream"
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "MP4/ISO-BMFF container"
    return "Unknown / data"

def _looks_like_double_extension(name: str) -> bool:
    parts = Path(name).name.lower().split(".")
    if len(parts) < 3:
        return False
    final_ext = "." + parts[-1]
    preceding_ext = "." + parts[-2]
    return preceding_ext in RISKY_DOUBLE_EXTENSIONS and final_ext in EXECUTABLE_EXTENSIONS

def _read_sample(path: Path, limit: int = 128 * 1024) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)

def inspect_file(path: str | os.PathLike[str], max_hash_bytes: int = 512 * 1024 * 1024) -> tuple[list[Finding], dict[str, Any]]:
    target = Path(path)
    metadata: dict[str, Any] = {
        "path": str(target),
        "name": target.name,
        "size": 0,
        "modified": "",
        "created": "",
        "signature": "Unread",
        "sha256": "",
        "entropy": None,
        "hash_status": "Not calculated",
        "hash_integrity": "Not checked",
        "observed_at": utc_now(),
    }
    findings: list[Finding] = []
    if max_hash_bytes < 0:
        raise ValueError("max_hash_bytes cannot be negative")
    try:
        initial = target.lstat()
        if stat_module.S_ISLNK(initial.st_mode):
            metadata["hash_status"] = "Skipped: symbolic link"
            metadata["error"] = "Symbolic links are not followed during file triage."
            return findings, metadata
        if not stat_module.S_ISREG(initial.st_mode):
            metadata["hash_status"] = "Skipped: not a regular file"
            return findings, metadata

        metadata["size"] = initial.st_size
        metadata["modified"] = datetime.fromtimestamp(initial.st_mtime, timezone.utc).astimezone().isoformat(timespec="seconds")
        # On POSIX st_ctime is metadata-change time, not creation time. Keep
        # the legacy field but label its meaning rather than overclaiming.
        if os.name == "nt":
            metadata["created"] = datetime.fromtimestamp(initial.st_ctime, timezone.utc).astimezone().isoformat(timespec="seconds")
            metadata["created_label"] = "Creation time (Windows ctime)"
        else:
            metadata["created"] = datetime.fromtimestamp(initial.st_ctime, timezone.utc).astimezone().isoformat(timespec="seconds")
            metadata["created_label"] = "Metadata change time (POSIX ctime)"

        sample = _read_sample(target)
        metadata["signature"] = identify_signature(sample)
        metadata["entropy"] = round(entropy(sample), 3)

        suffix = target.suffix.lower()
        attributes = getattr(initial, "st_file_attributes", 0)
        hidden_flag = getattr(stat_module, "FILE_ATTRIBUTE_HIDDEN", 0x2)
        hidden = target.name.startswith(".") or bool(attributes & hidden_flag)
        if suffix in EXECUTABLE_EXTENSIONS:
            severity = "Medium" if suffix in SCRIPT_EXTENSIONS else "Info"
            findings.append(Finding(
                severity, "Executable or script file", str(target),
                f"File extension {suffix} is executable or script-capable; this is not proof of maliciousness.",
                size=initial.st_size,
            ))
        if _looks_like_double_extension(target.name):
            findings.append(Finding(
                "High", "Potentially deceptive double extension", str(target),
                "The filename uses a document/media-like extension before an executable extension.",
                size=initial.st_size,
            ))
        if hidden and suffix in EXECUTABLE_EXTENSIONS:
            findings.append(Finding(
                "Medium", "Hidden executable or script", str(target),
                "The file is hidden and has an executable/script-capable extension.",
                size=initial.st_size,
            ))
        if suffix in {".mp4", ".jpg", ".jpeg", ".png", ".pdf", ".txt"} and sample.startswith(b"MZ"):
            findings.append(Finding(
                "High", "Extension and content mismatch", str(target),
                "The file has a document/media extension but begins with an MZ executable header.",
                size=initial.st_size,
            ))
        if len(sample) >= 16 * 1024 and metadata["entropy"] >= 7.35 and suffix not in {".zip", ".gz", ".7z", ".rar", ".png", ".jpg", ".jpeg", ".mp4", ".mp3"}:
            findings.append(Finding(
                "Low", "High-entropy sample", str(target),
                f"Sample entropy is {metadata['entropy']}/8.0. Compression or encryption can also cause high entropy.",
                size=initial.st_size,
            ))

        # Stamp the finding now, even if the later hashing attempt fails.
        observed = metadata["observed_at"]
        for finding in findings:
            finding.observed_at = observed

        if initial.st_size <= max_hash_bytes:
            try:
                metadata["sha256"] = sha256_file(target, expected_stat=initial)
                metadata["hash_status"] = "Complete SHA-256"
                metadata["hash_integrity"] = "Stable during read (identity, size, and mtime verified)"
                for finding in findings:
                    finding.sha256 = metadata["sha256"]
            except RuntimeError as exc:
                metadata["hash_status"] = "Discarded: source changed during hashing"
                metadata["hash_integrity"] = "Changed while read; no digest retained"
                metadata["error"] = str(exc)
        else:
            metadata["hash_status"] = f"Skipped: file exceeds remaining hash budget of {max_hash_bytes} bytes"

    except OSError as exc:
        metadata["error"] = f"{type(exc).__name__}: {exc}"
        metadata["hash_status"] = "Failed: read error"
        metadata["hash_integrity"] = "Could not verify"
    return findings, metadata

def scan_directory(
    root: str | os.PathLike[str],
    max_files: int = 2000,
    max_depth: int = 8,
    max_hash_bytes: int = 512 * 1024 * 1024,
    max_total_hash_bytes: int = 2 * 1024 * 1024 * 1024,
) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
    base = Path(root).expanduser()
    findings: list[Finding] = []
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if max_files < 1 or max_depth < 0 or max_hash_bytes < 0 or max_total_hash_bytes < 0:
        raise ValueError("Scan limits must be non-negative and max_files must be at least 1")
    if base.is_symlink() or not base.exists() or not base.is_dir():
        raise ValueError(f"Directory does not exist, is a symlink, or is not a directory: {base}")

    count = 0
    hashed_bytes = 0
    base_depth = len(base.resolve().parts)
    def _walk_error(exc: OSError) -> None:
        errors.append(f"Directory traversal error: {getattr(exc, 'filename', '') or ''}: {exc}")

    for current, dirs, files in os.walk(base, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        depth = len(current_path.resolve().parts) - base_depth
        dirs[:] = sorted(d for d in dirs if d not in {"$Recycle.Bin", "System Volume Information"} and not (current_path / d).is_symlink())
        if depth >= max_depth:
            dirs[:] = []
        for name in sorted(files, key=str.casefold):
            if count >= max_files:
                errors.append(f"Scan stopped at configured maximum of {max_files} files.")
                return findings, records, errors
            target = current_path / name
            if target.is_symlink():
                continue
            count += 1
            remaining_budget = max(0, max_total_hash_bytes - hashed_bytes)
            effective_hash_cap = min(max_hash_bytes, remaining_budget)
            file_findings, metadata = inspect_file(target, max_hash_bytes=effective_hash_cap)
            if metadata.get("sha256"):
                hashed_bytes += int(metadata.get("size") or 0)
            elif int(metadata.get("size") or 0) > 0 and remaining_budget < max_hash_bytes:
                metadata["hash_status"] = f"Skipped: total scan hash budget ({max_total_hash_bytes} bytes) reached"
            records.append(metadata)
            findings.extend(file_findings)
            if metadata.get("error"):
                errors.append(f"{target}: {metadata['error']}")
    return findings, records, errors

def collect_system_info() -> dict[str, str]:
    info = {
        "Computer": platform.node() or "Unknown",
        "User": os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown",
        "Operating system": platform.platform(),
        "Windows version": platform.version(),
        "Architecture": platform.machine(),
        "Python": sys.version.split()[0],
        "Collection time": utc_now(),
        "Elevated": "Unknown",
    }
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            memory = MEMORYSTATUSEX()
            memory.dwLength = ctypes.sizeof(memory)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
                info["RAM"] = f"{memory.ullTotalPhys // (1024**3)} GiB"
            try:
                info["Elevated"] = "Yes" if ctypes.windll.shell32.IsUserAnAdmin() else "No"
            except Exception:
                pass
        except Exception:
            pass
    return info

def _filetime_to_iso(filetime: int) -> str:
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)
        return dt.astimezone().isoformat(timespec="seconds")
    except (OverflowError, ValueError):
        return ""

def collect_usb_history() -> tuple[list[ForensicEvent], list[CollectionNote]]:
    events: list[ForensicEvent] = []
    notes: list[CollectionNote] = []
    if os.name != "nt":
        return events, [CollectionNote("USB Registry", "Unavailable", "USB registry collection is supported on Windows only.")]
    import winreg

    targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "HKLM USBSTOR"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB", "HKLM USB"),
    ]
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    for hive, path, label in targets:
        try:
            with winreg.OpenKey(hive, path, 0, access) as root_key:
                device_count = winreg.QueryInfoKey(root_key)[0]
                for i in range(device_count):
                    try:
                        device_name = winreg.EnumKey(root_key, i)
                        with winreg.OpenKey(root_key, device_name, 0, access) as device_key:
                            instance_count = winreg.QueryInfoKey(device_key)[0]
                            if instance_count == 0:
                                instance_count = 1
                            for j in range(instance_count):
                                try:
                                    instance_name = winreg.EnumKey(device_key, j) if winreg.QueryInfoKey(device_key)[0] else ""
                                    key_path = path + "\\" + device_name + ("\\" + instance_name if instance_name else "")
                                    with winreg.OpenKey(hive, key_path, 0, access) as instance_key:
                                        values = {}
                                        for value_name in ("FriendlyName", "DeviceDesc", "Mfg", "Service", "Class"):
                                            try:
                                                values[value_name] = str(winreg.QueryValueEx(instance_key, value_name)[0])
                                            except OSError:
                                                pass
                                        last_write = winreg.QueryInfoKey(instance_key)[2]
                                        stamp = _filetime_to_iso(last_write) if last_write else ""
                                        title = values.get("FriendlyName") or values.get("DeviceDesc") or device_name
                                        details = (
                                            f"Registry path: {key_path}; Instance: {instance_name or 'n/a'}; "
                                            f"Manufacturer: {values.get('Mfg', 'Unknown')}; "
                                            f"Service: {values.get('Service', 'Unknown')}; "
                                            "Registry LastWrite is a key-modification timestamp, not definitive proof of connection time."
                                        )
                                        events.append(ForensicEvent(
                                            timestamp=stamp, category="USB device", source=label,
                                            title=title, details=details, severity="Info",
                                        ))
                                except OSError as exc:
                                    notes.append(CollectionNote(label, "Partial", f"Could not read one device instance: {exc}"))
                    except OSError as exc:
                        notes.append(CollectionNote(label, "Partial", f"Could not enumerate a device: {exc}"))
            notes.append(CollectionNote(label, "OK", f"Enumerated {device_count} device identifiers."))
        except FileNotFoundError:
            notes.append(CollectionNote(label, "Not found", "Registry key was not present."))
        except PermissionError:
            notes.append(CollectionNote(label, "Access denied", "Run elevated to access this registry area, if appropriate."))
        except OSError as exc:
            notes.append(CollectionNote(label, "Error", str(exc)))

    setupapi = Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.dev.log"
    try:
        if setupapi.is_file():
            size = setupapi.stat().st_size
            if size <= 32 * 1024 * 1024:
                text = setupapi.read_text(encoding="utf-8", errors="replace")
                matches = []
                for line_no, line in enumerate(text.splitlines(), 1):
                    upper = line.upper()
                    if "USBSTOR" in upper or "VID_" in upper and "PID_" in upper:
                        matches.append((line_no, line.strip()[:300]))
                for line_no, line in matches[-250:]:
                    events.append(ForensicEvent(
                        timestamp="", category="USB / driver install", source="setupapi.dev.log",
                        title="USB-related SetupAPI entry",
                        details=f"Line {line_no}: {line}",
                        severity="Info",
                    ))
                notes.append(CollectionNote("SetupAPI log", "OK", f"Parsed {len(matches)} matching lines; retained up to 250 newest lines."))
            else:
                notes.append(CollectionNote("SetupAPI log", "Skipped", "Log exceeds 32 MiB safety limit."))
        else:
            notes.append(CollectionNote("SetupAPI log", "Not found", str(setupapi)))
    except OSError as exc:
        notes.append(CollectionNote("SetupAPI log", "Error", str(exc)))
    return sorted(events, key=lambda e: e.timestamp or "", reverse=True), notes

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$records = New-Object System.Collections.Generic.List[object]
$notes = New-Object System.Collections.Generic.List[string]
$logs = @(
    'System',
    'Application',
    'Security',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
    'Microsoft-Windows-Kernel-PnP/Configuration'
)
foreach ($log in $logs) {
    try {
        $items = Get-WinEvent -LogName $log -MaxEvents 120 -ErrorAction Stop
        foreach ($e in $items) {
            $records.Add([pscustomobject]@{
                LogName = [string]$e.LogName
                Provider = [string]$e.ProviderName
                Id = [int]$e.Id
                Level = [string]$e.LevelDisplayName
                TimeCreated = if ($e.TimeCreated) { $e.TimeCreated.ToString('o') } else { '' }
                RecordId = [string]$e.RecordId
                Message = if ($e.Message) { [string]$e.Message } else { '' }
            })
        }
        $notes.Add("$log : collected $($items.Count) recent events")
    } catch {
        $notes.Add("$log : $($_.Exception.Message)")
    }
}
$result = [pscustomobject]@{ Events = @($records); Notes = @($notes) }
ConvertTo-Json -InputObject $result -Depth 4 -Compress
"""

def parse_event_payload(payload: str) -> tuple[list[ForensicEvent], list[CollectionNote]]:
    if len(payload) > 32 * 1024 * 1024:
        raise ValueError("Windows event payload exceeded the 32 MiB safety limit")
    data = json.loads(payload)
    if isinstance(data, list):
        rows, raw_notes = data, []
    elif isinstance(data, dict):
        rows = data.get("Events", data.get("events", [])) or []
        raw_notes = data.get("Notes", data.get("notes", [])) or []
    else:
        raise ValueError("Unexpected Windows event payload format")
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise ValueError("Windows event payload did not contain an event list")
    events: list[ForensicEvent] = []
    for row in rows[:5000]:
        if not isinstance(row, dict):
            continue
        event_id = str(row.get("Id", ""))
        log_name = str(row.get("LogName", "Unknown"))
        provider = str(row.get("Provider", "Unknown"))
        message = str(row.get("Message", "")).strip()
        # Avoid huge event messages in reports/UI.
        message = message[:4000]
        severity = "Info"
        if event_id in {"4625", "1102", "4697", "7045", "1116", "1117"}:
            severity = "High" if event_id in {"1102", "1116", "4697", "7045"} else "Medium"
        elif event_id in {"4688", "4624", "4634", "4648", "4720"}:
            severity = "Medium"
        title = f"Event ID {event_id} — {provider}"
        events.append(ForensicEvent(
            timestamp=str(row.get("TimeCreated", "")),
            category=f"Windows Event Log / {log_name}",
            source=provider,
            title=title,
            details=message,
            severity=severity,
            record_id=str(row.get("RecordId", "")),
        ))
    notes = [CollectionNote("Windows Event Logs", "Info", str(note)[:2000]) for note in raw_notes[:100] if note is not None] if isinstance(raw_notes, list) else []
    if len(rows) > 5000:
        notes.append(CollectionNote("Windows Event Logs", "Partial", "Event payload exceeded 5,000 rows; remaining rows were ignored."))
    return sorted(events, key=lambda e: e.timestamp or "", reverse=True), notes

def collect_windows_event_logs(timeout: int = 90) -> tuple[list[ForensicEvent], list[CollectionNote]]:
    if os.name != "nt":
        return [], [CollectionNote("Windows Event Logs", "Unavailable", "Windows Event Log collection is supported on Windows only.")]
    shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or "powershell.exe"
    try:
        run_options: dict[str, Any] = {}
        if os.name == "nt":
            run_options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        completed = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_SCRIPT],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, **run_options,
        )
        if completed.returncode != 0 and not completed.stdout.strip():
            return [], [CollectionNote("Windows Event Logs", "Error", (completed.stderr or "PowerShell returned a non-zero exit code.")[:1500])]
        output = completed.stdout.strip()
        if not output:
            return [], [CollectionNote("Windows Event Logs", "Error", (completed.stderr or "No output returned.")[:1500])]
        events, notes = parse_event_payload(output)
        if completed.stderr.strip():
            notes.append(CollectionNote("PowerShell", "Warning", completed.stderr.strip()[:1000]))
        if completed.returncode != 0:
            notes.append(CollectionNote("PowerShell", "Warning", f"Exit code: {completed.returncode}"))
        return events, notes
    except subprocess.TimeoutExpired:
        return [], [CollectionNote("Windows Event Logs", "Timeout", f"PowerShell exceeded {timeout} seconds.")]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [], [CollectionNote("Windows Event Logs", "Error", f"{type(exc).__name__}: {exc}")]

def collect_baseline() -> CollectionBundle:
    bundle = CollectionBundle(system_info=collect_system_info())
    usb_events, usb_notes = collect_usb_history()
    log_events, log_notes = collect_windows_event_logs()
    bundle.usb_events = usb_events
    bundle.log_events = log_events
    bundle.notes.extend(usb_notes)
    bundle.notes.extend(log_notes)
    bundle.notes.append(CollectionNote(
        "Collection scope", "Important",
        "This is a bounded triage collection of selected local sources, not a full forensic disk image or a guarantee that all activity is present."
    ))
    return bundle

def severity_rank(severity: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(severity, 5)
