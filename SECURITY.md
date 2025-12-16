# Security policy / non-offensive scope

`dfirlab` is designed for **lawful, defensive** DFIR workflows only.

## Out of scope (won't be implemented)

- Exploitation, persistence, stealth
- Credential theft, password cracking, token extraction
- Bypassing access controls, “unlocking phones”, forensic bypasses
- Remote collection agents or anything enabling unauthorized access

## Data handling

- Offline-first: no evidence exfiltration features.
- Evidence is treated as read-only; processing occurs on copies inside the case vault (or by referencing a provided path without modifying it).
