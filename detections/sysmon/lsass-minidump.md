\# Day 11 — Detection Engineering: LSASS Dump Attempt (rundll32 + comsvcs.dll,MiniDump)



\## Objective

Detect attempted LSASS memory dumping using the `comsvcs.dll,MiniDump` technique via `rundll32.exe` on Windows endpoints.



\## Threat Context

LSASS dumping is a common credential access technique used to extract credentials from memory.

Even if endpoint protection blocks execution, the \*\*attempted execution\*\* is valuable telemetry for SOC detection.



\## Data Source

\- Log source: Sysmon (Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (Process Create)

\- Wazuh decoder: windows\_eventchannel

\- Agent: WIN-ENDPOINT-01



\## MITRE ATT\&CK Mapping

\- \*\*T1003.001 — OS Credential Dumping: LSASS Memory\*\*

\- Tactic: Credential Access



\## Detection Strategy (Layered Rules)

This detection is implemented in layers to support SOC triage and prioritization:



\### Rule 200609 — Baseline Visibility (Level 10)

Triggers on:

\- `rundll32.exe`

\- CommandLine contains `comsvcs.dll,MiniDump`



Purpose:

\- Provide reliable baseline detection of this technique.



\### Rule 200610 — High-Signal Escalation (Level 13)

Triggers when baseline rule fires AND the parent process is suspicious:

\- powershell.exe / pwsh.exe / cmd.exe / wscript.exe / cscript.exe / mshta.exe



Purpose:

\- Increase confidence by adding attacker-like execution context.



\### Rule 200611 — High-Risk Escalation (Level 14)

Triggers when high-signal rule fires AND:

\- IntegrityLevel = High

\- User is NOT `NT AUTHORITY\\SYSTEM`



Purpose:

\- Flag elevated privilege credential access attempts as high priority SOC alerts.



\## Rules (local\_rules.xml)

```xml

<rule id="200609" level="10">

&nbsp; <if\_group>sysmon\_event1</if\_group>

&nbsp; <field name="win.eventdata.image" type="pcre2">(?i)\\\\rundll32\\.exe$</field>

&nbsp; <field name="win.eventdata.commandLine" type="pcre2">(?i)comsvcs\\.dll,MiniDump</field>

&nbsp; <description>Credential Access: LSASS dump attempt via rundll32 comsvcs.dll,MiniDump (Sysmon EID 1)</description>

&nbsp; <mitre><id>T1003.001</id></mitre>

</rule>



<rule id="200610" level="13">

&nbsp; <if\_sid>200609</if\_sid>

&nbsp; <field name="win.eventdata.parentImage" type="pcre2">(?i)\\\\(powershell\\.exe|pwsh\\.exe|cmd\\.exe|wscript\\.exe|cscript\\.exe|mshta\\.exe)$</field>

&nbsp; <description>HIGH SIGNAL: LSASS dump attempt via MiniDump launched from suspicious parent process</description>

&nbsp; <mitre><id>T1003.001</id></mitre>

</rule>



<rule id="200611" level="14">

&nbsp; <if\_sid>200610</if\_sid>

&nbsp; <field name="win.eventdata.integrityLevel" type="pcre2">(?i)High</field>

&nbsp; <field name="win.eventdata.user" type="pcre2">(?i)^(?!NT AUTHORITY\\\\\\\\SYSTEM).\*</field>

&nbsp; <description>HIGH RISK Credential Access: LSASS dump attempt with elevated privileges</description>

&nbsp; <mitre><id>T1003.001</id></mitre>

</rule>



\## Validation

\### Telemetry Generation

Executed on Windows endpoint:



* rundll32.exe comsvcs.dll,MiniDump



Note:



* Windows Defender may flag this as malicious. Detection is based on execution attempt telemetry (Sysmon EID 1).



\## Evidence (Wazuh)

Validated in:



* archives.json (raw Sysmon EID 1 event observed)
* alerts.json (rules 200609, 200610, 200611 fired)
* Wazuh Dashboard (Security Events)



\## Outcome

Established a SOC-ready, layered detection for credential dumping attempts with prioritization based on suspicious execution context and elevated privilege level.

