"""Human-readable AntiSkid report exporters (HTML and CSV)."""
from __future__ import annotations

import csv
import html
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable

from antiskid_core import APP_VERSION, CollectionBundle, ForensicEvent, Finding

def _safe_csv(value: object) -> str:
    text = str(value if value is not None else "")
    # Excel and compatible spreadsheet apps may evaluate formulas even when
    # preceded by whitespace. Check the first non-whitespace character.
    probe = text.lstrip(" \t\r\n")
    if probe.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _validate_report_target(destination: str | Path, protected_paths: Iterable[str | Path] = ()) -> Path:
    target = Path(destination).expanduser()
    if not target.name:
        raise ValueError("A report filename is required")
    target_resolved = target.resolve(strict=False)
    for item in protected_paths:
        try:
            protected = Path(item).expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if target_resolved == protected:
            raise ValueError("Report destination matches an inspected evidence file; choose a separate output path")
    return target


def _atomic_write_text(target: Path, content: str, encoding: str = "utf-8") -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise

def export_html_report(
    bundle: CollectionBundle,
    destination: str | Path,
    case_name: str = "Untitled case",
    file_records: list[dict] | None = None,
    protected_paths: Iterable[str | Path] = (),
) -> Path:
    target = _validate_report_target(destination, protected_paths)
    events = bundle.timeline()
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    def esc(value: object) -> str:
        return html.escape(str(value if value is not None else ""), quote=True)

    system_rows = "".join(
        f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>"
        for key, value in bundle.system_info.items()
    )
    finding_rows = "".join(
        "<tr>"
        f"<td class='sev {esc(f.severity.lower())}'>{esc(f.severity)}</td>"
        f"<td>{esc(f.title)}</td><td>{esc(f.path)}</td>"
        f"<td>{esc(f.reason)}</td><td><code>{esc(f.sha256 or 'Not calculated')}</code></td>"
        "</tr>" for f in sorted(bundle.findings, key=lambda x: x.severity)
    ) or "<tr><td colspan='5'>No file triage findings were recorded.</td></tr>"
    event_rows = "".join(
        "<tr>"
        f"<td>{esc(e.timestamp)}</td><td class='sev {esc(e.severity.lower())}'>{esc(e.severity)}</td>"
        f"<td>{esc(e.category)}</td><td>{esc(e.source)}</td>"
        f"<td>{esc(e.title)}</td><td class='details'>{esc(e.details)}</td>"
        "</tr>" for e in events
    ) or "<tr><td colspan='6'>No timeline events were recorded.</td></tr>"
    note_rows = "".join(
        f"<tr><td>{esc(n.source)}</td><td>{esc(n.status)}</td><td>{esc(n.message)}</td></tr>"
        for n in bundle.notes
    ) or "<tr><td colspan='3'>No collection notes.</td></tr>"
    file_rows = ""
    for item in (file_records or []):
        file_rows += (
            "<tr>"
            f"<td>{esc(item.get('name',''))}</td><td>{esc(item.get('path',''))}</td>"
            f"<td>{esc(item.get('size',''))}</td><td>{esc(item.get('signature',''))}</td>"
            f"<td>{esc(item.get('modified',''))}</td><td><code>{esc(item.get('sha256') or item.get('hash_status',''))}</code></td>"
            f"<td>{esc(item.get('hash_integrity',''))}</td>"
            "</tr>"
        )
    if not file_rows:
        file_rows = "<tr><td colspan='7'>No file inventory was collected.</td></tr>"

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AntiSkid Forensic Report — {esc(case_name)}</title>
<style>
:root{{--bg:#201c25;--panel:#2e2933;--line:#6f6977;--text:#eeeaf2;--muted:#b7afbd;--accent:#c2b7d2;--red:#d77979;--amber:#d5b36a;--green:#91bd9b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px Consolas,"Courier New",monospace;line-height:1.5}}
main{{max-width:1250px;margin:28px auto;padding:0 18px}}header,.panel{{background:var(--panel);border:2px solid var(--line);box-shadow:inset 1px 1px #514b58, inset -1px -1px #17151b;margin-bottom:18px;padding:18px}}
h1{{margin:0;font-size:25px;letter-spacing:2px}}h2{{font-size:17px;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:8px}}
small,.muted{{color:var(--muted)}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid #514b58;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#393440;color:var(--accent)}}code{{font-size:11px;overflow-wrap:anywhere}}
.sev{{font-weight:bold}}.high,.critical{{color:var(--red)}}.medium{{color:var(--amber)}}.low,.info{{color:var(--green)}}.details{{white-space:pre-wrap;max-width:430px}}
.notice{{border-left:4px solid var(--amber);padding:10px;background:#28232d}}footer{{color:var(--muted);font-size:11px;padding:16px;text-align:center}}
@media print{{body{{background:white;color:#111;font-family:Arial,sans-serif}}header,.panel{{box-shadow:none;background:white;border:1px solid #999;break-inside:avoid}}th{{background:#eee;color:#111}}td,th{{border-color:#aaa}}}}
</style></head><body><main>
<header><h1>ANTISKID // DIGITAL FORENSICS</h1>
<p>{esc(case_name)}</p><small>Generated: {esc(generated)} · Version: {esc(APP_VERSION)} · Local collection only</small></header>
<div class="notice"><b>Interpretation notice:</b> This report is a bounded triage snapshot. Heuristic indicators are not proof of malware, registry timestamps are not definitive connection times, and missing events do not prove that an action did not occur. Preserve original evidence and validate important findings independently.</div>
<section class="panel"><h2>01 — SYSTEM PROFILE</h2><table>{system_rows or '<tr><td>No system information.</td></tr>'}</table></section>
<section class="panel"><h2>02 — FILE TRIAGE FINDINGS ({len(bundle.findings)})</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Path</th><th>Reason</th><th>SHA-256</th></tr></thead><tbody>{finding_rows}</tbody></table></section>
<section class="panel"><h2>03 — FILE INVENTORY ({len(file_records or [])})</h2><table><thead><tr><th>Name</th><th>Path</th><th>Size</th><th>Signature</th><th>Modified</th><th>SHA-256 / Status</th><th>Hash integrity</th></tr></thead><tbody>{file_rows}</tbody></table></section>
<section class="panel"><h2>04 — UNIFIED TIMELINE ({len(events)})</h2><table><thead><tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Source</th><th>Event</th><th>Details</th></tr></thead><tbody>{event_rows}</tbody></table></section>
<section class="panel"><h2>05 — COLLECTION STATUS & LIMITATIONS</h2><table><thead><tr><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>{note_rows}</tbody></table></section>
<footer>AntiSkid by aymen · Read-only endpoint triage · This report contains potentially sensitive system metadata. Store and share it securely.</footer>
</main></body></html>"""
    _atomic_write_text(target, document, encoding="utf-8")
    return target

def export_csv_report(
    bundle: CollectionBundle,
    destination: str | Path,
    protected_paths: Iterable[str | Path] = (),
) -> Path:
    target = _validate_report_target(destination, protected_paths)
    import io
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["Timestamp", "Severity", "Category", "Source", "Title", "Details", "Record ID"])
    for event in bundle.timeline():
        writer.writerow([_safe_csv(getattr(event, field)) for field in (
            "timestamp", "severity", "category", "source", "title", "details", "record_id"
        )])
    writer.writerow([])
    writer.writerow(["Finding Severity", "Finding", "Path", "Reason", "SHA-256", "Size"])
    for finding in bundle.findings:
        writer.writerow([_safe_csv(getattr(finding, field)) for field in (
            "severity", "title", "path", "reason", "sha256", "size"
        )])
    _atomic_write_text(target, buffer.getvalue(), encoding="utf-8-sig")
    return target
