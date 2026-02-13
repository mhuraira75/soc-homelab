\# Detection Engineering: PsExec Execution (Sysmon EID 1)



\## Objective

Detect execution of Sysinternals PsExec (`psexec.exe` / `psexec64.exe`) on Windows endpoints using Sysmon Event ID 1 telemetry in Wazuh.



\## Why This Matters (SOC Context)

PsExec is a common administrative tool that is also frequently abused by attackers for remote execution and lateral movement. Detecting its execution provides high-signal visibility into potential hands-on-keyboard activity and remote command execution workflows.



\## Environment

\- SIEM: Wazuh (Manager / Indexer / Dashboard) on Ubuntu Server

\- Endpoint: WIN-ENDPOINT-01 (Windows 11)

\- Telemetry: Sysmon `Microsoft-Windows-Sysmon/Operational`

\- Event ID: 1 (Process Create)



\## MITRE ATT\&CK Mapping

\- \*\*T1569 — System Services\*\* (often used as PsExec creates/uses a service mechanism)

\- \*\*T1021 — Remote Services\*\* (associated technique family for lateral movement)



\## Detection Logic

Trigger an alert when Sysmon Event ID 1 shows the process image ends with:

\- `\\psexec.exe`

\- `\\psexec64.exe`



\## Wazuh Rule

Rule ID: \*\*200703\*\*



```xml

<!-- DAY 16 — PsExec Execution Detection -->

<rule id="200703" level="10">

&nbsp; <if\_group>sysmon\_event1</if\_group>

&nbsp; <field name="win.system.channel">Microsoft-Windows-Sysmon/Operational</field>

&nbsp; <field name="win.eventdata.image" type="pcre2">(?i)\\\\(psexec|psexec64)\\.exe$</field>

&nbsp; <description>Lateral Movement / Remote Execution: PsExec execution detected (Sysmon EID 1)</description>

&nbsp; <mitre>

&nbsp;   <id>T1569</id>

&nbsp;   <id>T1021</id>

&nbsp; </mitre>

</rule>



\## Validation

1. Executed PsExec on the endpoint:



* C:\\Tools\\PsExec\\psexec64.exe -accepteula cmd.exe



1. Confirmed alert generated in Wazuh:



* /var/ossec/logs/alerts/alerts.json



1. Confirmed rule fired:



* rule.id = 200703



\## Evidence to Capture 



* Sysmon Event Viewer showing EID 1 for psexec64.exe
* Wazuh Dashboard alert showing rule 200703
* alerts.json snippet filtered to rule 200703
