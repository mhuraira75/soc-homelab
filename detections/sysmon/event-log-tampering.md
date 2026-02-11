\# Defense Evasion Detection — Windows Event Log Clearing (Sysmon EID 1)



\## Objective



Detect attempts to clear Windows Event Logs using `wevtutil cl`, a common defense evasion technique used by attackers to remove forensic evidence.



\## Threat Context



Adversaries often attempt to erase logs after gaining access to a system to hide malicious activity. Clearing logs reduces visibility for incident responders and SOC analysts.



\## Data Source



\- Log Source: Sysmon

\- Event ID: 1 (Process Create)

\- Wazuh Decoder: windows\_eventchannel



\## MITRE ATT\&CK Mapping



\- T1070.001 — Indicator Removal on Host: Clear Windows Event Logs

\- Tactic: Defense Evasion



\## Detection Logic



Layered detection approach:



\### Visibility Rule



Detect execution of `wevtutil.exe`.



\### High-Signal Rule



Detect:



\- `wevtutil cl Application`

\- `wevtutil cl Security`

\- `wevtutil cl System`



These represent high-confidence indicators of log clearing activity.



\## Validation Steps



1\. Execute:

wevtutil cl Application

2\. Confirm Sysmon Event ID 1 in Event Viewer.

3\. Verify event ingestion in Wazuh archives.json.

4\. Confirm alert generation in alerts.json and Wazuh dashboard.





\## Result



Detection successfully generated alerts based on behavioural detection logic.



\## SOC Analyst Notes



\- Visibility rule supports hunting and baseline analysis.

\- High-signal rule reduces noise by focusing on sensitive log clearing commands.



