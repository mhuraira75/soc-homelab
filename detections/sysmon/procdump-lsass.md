\# Day 12 — Detection Engineering: ProcDump Targeting LSASS (Sysmon EID 1)



\## Objective

Detect credential dumping intent by identifying ProcDump executions targeting `lsass.exe` using Sysmon Process Create telemetry (Event ID 1) in Wazuh.



\## Threat Context

Dumping LSASS memory is a common credential access technique used to extract plaintext credentials, NTLM hashes, and Kerberos tickets. While modern Windows protections (e.g., PPL/Credential Guard) may block successful dumping, the execution attempt itself remains a high-confidence indicator of malicious intent.



\## Environment

\- SIEM: Wazuh (Manager / Indexer / Dashboard) on Ubuntu Server VM

\- Endpoint: Windows 11 (`WIN-ENDPOINT-01`) with Wazuh Agent

\- Telemetry: Sysmon → Wazuh (`windows\_eventchannel`)



\## Data Source

\- Log source: Microsoft-Windows-Sysmon/Operational

\- Event ID: \*\*1\*\* (Process Create)



\## MITRE ATT\&CK Mapping

\- \*\*T1003.001 — OS Credential Dumping: LSASS Memory\*\*

\- Tactic: \*\*Credential Access\*\*



\## Attack Simulation (Lab Validation)

ProcDump execution attempt (may fail with Access Denied on hardened Windows builds, which is expected):

```powershell

cd C:\\Tools\\Procdums

.\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp



\## Detection Strategy (Layered)

This day implements a layered approach:



\### Rule 200608 — Baseline Visibility

Detects ProcDump execution (EID 1) for visibility and hunting pivots.



\### Rule 200618 — High-Signal Detection

Detects ProcDump command-line intent targeting LSASS:



* procdump(64)?.exe



* -ma or -mp



* lsass / lsass.exe



This remains effective even when memory dumping is blocked, because detection is based on intent/attempt.





\## Wazuh Rule Logic (local\_rules.xml)

* 200608 (visibility): matches ProcDump image



* 200618 (high-signal): chained from 200608 and matches LSASS-targeting command line



\## Validation Evidence

* Alerts observed in Wazuh Dashboard:



1. 200608 — Credential Access (Visibility): ProcDump executed (Sysmon EID 1)
2. 200618 — Credential Access (High-Signal): ProcDump targeting LSASS (Sysmon EID 1)



* Telemetry confirmed in Wazuh archives.json for Sysmon EID 1 with command line containing:

1. procdump64.exe -accepteula -ma lsass.exe



\## Notes / Troubleshooting

* Sysmon EID 10 (ProcessAccess) may not be generated on modern Windows builds due to LSASS protections (PPL/Credential Guard). This detection intentionally uses EID 1 to remain reliable under hardened conditions.



* Regex tuning was required to match real ingested command line formatting (escaped quotes/backslashes).
