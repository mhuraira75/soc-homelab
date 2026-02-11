\# Day 14 — Detection Engineering: Discovery Commands (Sysmon EID 1)



\## Objective



Detect native Windows discovery commands commonly executed by attackers during post-compromise reconnaissance using Sysmon Event ID 1 telemetry in Wazuh.



---



\## Threat Context



After gaining initial access or privileges, attackers typically perform system and network discovery to understand:



\- Current user privileges

\- Local system information

\- Network connections

\- Available hosts and interfaces



These commands help attackers plan lateral movement and privilege escalation.



Common discovery commands include:



\- whoami

\- systeminfo

\- ipconfig

\- netstat

\- arp

\- net



---



\## Data Source



\- Log source: Sysmon (Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (Process Creation)

\- Wazuh decoder: windows\_eventchannel



---



\## MITRE ATT\&CK Mapping



\- T1082 — System Information Discovery

\- T1016 — System Network Configuration Discovery

\- T1049 — System Network Connections Discovery

\- T1087 — Account Discovery



---



\## Detection Logic



\### Visibility Rule



Detect execution of native Windows discovery utilities using process image matching.



Logic:



\- Sysmon Event ID 1

\- Process image matches common discovery tools



---



\### High-Signal Rule



Detect suspicious enumeration parameters frequently used during attacker reconnaissance:



Examples:



\- whoami /groups

\- netstat -ano

\- arp -a



Layered rule design improves detection quality by reducing noise and highlighting potentially malicious behaviour.



---



\## Validation



Telemetry was generated on Windows endpoint:



\- whoami /groups

\- systeminfo

\- netstat -ano

\- arp -a



Validation steps:



1\. Confirmed raw telemetry in archives.json

2\. Verified Sysmon Event ID = 1

3\. Confirmed alerts triggered in alerts.json

4\. Verified alerts visible in Wazuh dashboard



---



\## SOC Analyst Notes



Native administrative tools (LOLBins) are frequently abused by attackers because they blend into normal system activity.



Layered detections combining visibility and high-signal parameters help SOC analysts identify suspicious reconnaissance patterns without excessive false positives.



---



\## Outcome



Successfully implemented discovery detection aligned with MITRE ATT\&CK Discovery tactics using layered Wazuh rules based on real endpoint telemetry.

