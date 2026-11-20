# Changelog

## 0.2.0
- Removed the native Windows title caption and Tk File/Tools/Help menu; added themed minimize, maximize/restore, close, and drag controls.
- Improved file hashing integrity checks and symbolic-link handling.
- Made file-timeline timestamps stable at observation time.
- Made directory traversal deterministic and report traversal errors.
- Added event-payload size/schema limits and suppresses the PowerShell console window.
- Made report writes atomic, protected scanned source paths from report overwrite, and strengthened CSV formula-injection handling.
- Added regression tests for the new safety checks.


## 0.1.0 — Initial foundation
- Created AntiSkid desktop GUI using Tkinter/ttk.
- Added local system profile collection.
- Added USB registry enumeration and SetupAPI log parsing.
- Added bounded Windows Event Log snapshot via PowerShell.
- Added heuristic file triage, SHA-256 metadata, and bounded directory scanning.
- Added searchable unified timeline.
- Added HTML and CSV report export.
- Added collection notes and read-only/evidence-handling limitations.
- Added unit tests and Windows batch launchers.
