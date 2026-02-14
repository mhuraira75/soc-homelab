\# Detection Engineering — Certutil Download (Parent-Child Enrichment)



\## Objective

Detect suspicious use of `certutil.exe` for remote retrieval and elevate severity when execution is user-driven via `explorer.exe` (parent-child refinement).



\## Why this matters

`certutil.exe` is a Windows LOLBin commonly abused for downloading payloads (“living off the land”). Parent-child context reduces noise and increases confidence.



\## Data Source

\- Log source: Sysmon (Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (Process Create)

\- Fields used:

&nbsp; - `image`, `commandLine`

&nbsp; - `parentImage`, `parentCommandLine`



\## Detection Logic

\### Base behavior detection (download indicators)

Trigger on:

\- `image` ends with `certutil.exe`

\- AND command line contains any of:

&nbsp; - `-urlcache`

&nbsp; - `http://` or `https://`



\### High-confidence enrichment (parent-child)

Elevate when:

\- Parent process is `explorer.exe` (user-driven execution)



\## MITRE ATT\&CK

\- T1105 — Ingress Tool Transfer



\## Validation Evidence

\### Telemetry (Sysmon EID 1) captured in archives.json

Example:

\- Parent: `C:\\Windows\\explorer.exe`

\- Child: `C:\\Windows\\System32\\certutil.exe`

\- Command line includes: `-urlcache -split -f https://example.com ...`



\### Wazuh Alert Evidence (alerts.json)

\- Base rule fired: \*\*200705\*\* (level 12)

\- Enriched rule fired: \*\*200715\*\* (level 14)



\## Tuning Notes (False Positive Reduction)

\- Require download indicators (`-urlcache` and/or URL) to avoid benign certificate store operations.

\- Parent-child enrichment provides a confidence boost rather than replacing the base behavior rule.



\## Next Steps

\- Extend parent-child enrichment for:

&nbsp; - `cmd.exe`, `powershell.exe`

&nbsp; - Office apps (`winword.exe`, `excel.exe`, etc.) when Office telemetry is present

\- Replicate this pattern for other LOLBins (mshta, rundll32, regsvr32).



