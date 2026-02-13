\# LOLBins Behaviour Detection Pack (Sysmon EID 1) — rundll32, mshta, certutil, regsvr32



\## Objective

Develop and validate behavior-based detections for common Windows LOLBins by identifying suspicious parent-child execution patterns (scripting shell → LOLBin) using Sysmon Process Create telemetry (Event ID 1) in Wazuh.



\## Threat Context

LOLBins (Living-off-the-Land Binaries) are legitimate Windows utilities frequently abused by attackers for execution, defense evasion, and payload staging. Rather than detecting the binary alone, this detection focuses on behavior: scripting shells spawning LOLBins.



\## Data Source

\- Log Source: Sysmon (Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (Process Create)

\- Wazuh decoding: windows\_eventchannel

\- Endpoint: WIN-ENDPOINT-01 (Windows 11 agent)



\## Detection Approach (SOC Analyst Mindset)

Instead of alerting on LOLBins generically (high false positives), detect suspicious chaining:

\- `powershell.exe` / `cmd.exe` → LOLBin execution



This pattern is frequently observed in real-world intrusion chains (scripted execution → LOLBin staging/execution).



\## Implemented Wazuh Rules (local\_rules.xml)



\### Rule 200704 — rundll32 spawned by PowerShell/cmd

\- Trigger condition:

&nbsp; - Image ends with `rundll32.exe`

&nbsp; - Parent image ends with `powershell.exe` OR `cmd.exe`



\*\*MITRE ATT\&CK\*\*

\- T1218.011 — Signed Binary Proxy Execution: Rundll32

\- Tactics: Execution, Defense Evasion



\### Rule 200714 — regsvr32/mshta/certutil spawned by PowerShell/cmd

\- Trigger condition:

&nbsp; - Image ends with `regsvr32.exe` OR `mshta.exe` OR `certutil.exe`

&nbsp; - Parent image ends with `powershell.exe` OR `cmd.exe`



\*\*MITRE ATT\&CK\*\*

\- T1218 — Signed Binary Proxy Execution (general LOLBins proxy execution category)

\- Tactics: Execution, Defense Evasion



\## Validation (Telemetry First → Rule Second)

\### Telemetry confirmation

Validated Sysmon EID 1 events were present in `archives.json` prior to rule creation.



\### Trigger tests (safe)

\- rundll32:

&nbsp; - `rundll32.exe url.dll,FileProtocolHandler https://example.com`

\- mshta:

&nbsp; - `mshta.exe https://example.com`

\- certutil:

&nbsp; - `certutil.exe -urlcache -f https://example.com testfile.txt`



\### Alert verification

Confirmed alerts fired in:

\- `/var/ossec/logs/alerts/alerts.json`

\- Wazuh Dashboard alerts view



\## Notes / Tuning Ideas (Next Iteration)

\- Reduce false positives by adding allowlists for known admin tools or trusted parent processes.

\- Increase severity when LOLBins are launched from Office apps (e.g., WINWORD/EXCEL) or browsers.

\- Add command-line indicators for stronger signals (e.g., `javascript:`, `mshtml.dll,RunHTMLApplication`, unusual remote URLs, temp/user-writable paths).



