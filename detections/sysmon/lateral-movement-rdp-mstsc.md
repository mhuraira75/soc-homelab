\# Lateral Movement Visibility — RDP Client Execution (mstsc /v) (Sysmon EID 1)



\## Objective

Detect execution of the native Windows RDP client (`mstsc.exe`) where a target is specified using `/v:`. This provides visibility into potential lateral movement attempts.



\## Threat Context

Remote Desktop Protocol (RDP) is a common method for lateral movement. Attackers often use built-in tooling to blend in with normal admin behavior. Capturing `mstsc /v:<target>` provides destination context and supports investigation/correlation.



\## Data Source

\- \*\*Log source:\*\* Sysmon (Microsoft-Windows-Sysmon/Operational)

\- \*\*Event ID:\*\* 1 (Process Create)

\- \*\*Endpoint:\*\* WIN-ENDPOINT-01 (Windows 11)

\- \*\*Ingestion:\*\* Wazuh agent → Wazuh manager (`windows\_eventchannel`)



\## MITRE ATT\&CK Mapping

\- \*\*T1021.001 — Remote Services: Remote Desktop Protocol\*\*



\## Telemetry Generation (Test)

Executed on endpoint:

```bat

mstsc /v:10.10.10.10





\## Detection Logic



This detection is implemented as a layered rule:



* Parent rule: confirms Sysmon Process Create visibility (EID 1)
* Child rule: identifies mstsc.exe executions used with a target (/v:)



Key match:



* win.eventdata.image ends with mstsc.exe



Note: The rule uses PCRE2 regex (type="pcre2") to ensure reliable handling of regex features like (?i) (case-insensitive) and end-of-string anchors.



\## Wazuh Rule



<!-- DAY 15 -->

<!-- Lateral Movement -->

<group name="local,lateral\_movement">



&nbsp; <rule id="200702" level="3">

&nbsp;   <if\_group>sysmon\_event1</if\_group>

&nbsp;   <field name="win.system.eventID">^1$</field>

&nbsp;   <description>Visibility: Sysmon Process Create detected</description>

&nbsp; </rule>



&nbsp; <rule id="200712" level="10">

&nbsp;   <if\_sid>200702</if\_sid>

&nbsp;   <field name="win.eventdata.image" type="pcre2">(?i)mstsc\\.exe$</field>

&nbsp;   <description>Lateral Movement (Visibility): RDP client execution with target specified (mstsc /v)</description>

&nbsp;   <mitre>

&nbsp;     <id>T1021.001</id>

&nbsp;   </mitre>

&nbsp; </rule>



</group>





\## Validation Evidence

Alert confirmed in /var/ossec/logs/alerts/alerts.json:



* Rule ID: 200712



* Image: C:\\\\Windows\\\\System32\\\\mstsc.exe



* CommandLine: mstsc /v:10.10.10.10



\## Notes / Tuning Ideas



To reduce noise and increase value in production:



* Add /v: argument matching (target specified) when command-line field matching is supported reliably



* Consider allowlisting known admin jump hosts or approved destination ranges



* Correlate with authentication logs (e.g., successful logons, NTLM, RDP logon types) for higher-confidence detections
