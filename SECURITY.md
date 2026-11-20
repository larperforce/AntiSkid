# AntiSkid Security and Evidence Handling Notes

## Intended use
AntiSkid is intended for defensive triage on computers you own or are authorized to examine.

## Read-only collection
The current collectors read:
- Host/platform information.
- Selected local Registry keys under USB enumeration paths.
- Selected local Windows Event Log channels through a fixed PowerShell query.
- File metadata and file contents for sampling/hash calculation in a user-selected directory.

The application does not execute inspected files, intentionally modify registry keys, clear event logs, disable services, alter audit policy, or upload evidence. Reading file content may update filesystem access metadata on systems where last-access updates are enabled.

## Evidence preservation
This application is not a write blocker and does not create a forensic disk image. A live Windows system changes while it is running. For evidentiary work, use an approved acquisition process, preserve original media, maintain chain-of-custody documentation, and validate hashes with an independent tool.

Do not treat a Registry key LastWrite value as an exact USB connection time. Do not treat heuristic file findings as a malware verdict. Do not treat missing log records as proof that an action did not happen.

## Permissions
Some sources may require an elevated process or specific event-log permissions. AntiSkid does not auto-elevate. The Collection Notes page should be checked after each run.

## Output sensitivity
HTML/CSV reports can contain usernames, machine names, timestamps, USB device identifiers, paths, and event messages. Store and share reports securely.

## Current limitations in 0.2.0
- Recent event-log snapshot is limited to 120 events per configured log channel.
- Some event channels may not be enabled or installed on a system.
- USB registry enumeration does not reconstruct a complete connection/disconnection history.
- File triage is heuristic and does not perform AV signature scanning or sandbox execution.
- SHA-256 is skipped for files larger than 512 MiB by default.
- The directory walker is bounded to 2,000 files, depth 8, and a 2 GiB aggregate hashing budget.
- No raw disk, memory, deleted-file, unallocated-space, or offline Registry hive acquisition is included.


## 0.2.0 safeguards

- File hashing rejects symlinks and discards the digest when file identity, size, or modification time changes during hashing.
- Directory traversal is sorted, bounded, and reports traversal errors.
- Event-log payloads have strict size and row limits.
- HTML/CSV output is written through a temporary file and atomically replaced after successful generation.
- Export destinations are checked against the current file inventory to prevent accidental overwrite of scanned evidence.
