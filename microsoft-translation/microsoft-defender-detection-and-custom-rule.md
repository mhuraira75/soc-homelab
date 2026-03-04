\# Phase 5 — Day 3  

\# Microsoft Defender Data Model \& Detection Translation



\## Overview



Day 3 focused on understanding the Microsoft Defender XDR telemetry model and translating existing SOC detection engineering logic from the home lab environment into Microsoft-native schemas and KQL queries.



The objective was to demonstrate how detection logic developed using Sysmon, Suricata, firewall telemetry, and cloud logs can be mapped into Microsoft Defender and Microsoft Sentinel environments.



The day also included the creation of a working detection rule using Log Analytics query telemetry.



---



\# Microsoft Security Telemetry Model



Microsoft Defender XDR uses structured telemetry tables for endpoint, identity, and network monitoring.



Key endpoint telemetry tables include:



| Table | Purpose |

|------|------|

| DeviceProcessEvents | Process execution telemetry |

| DeviceNetworkEvents | Network connection telemetry |

| DeviceFileEvents | File activity monitoring |

| IdentityLogonEvents | Identity authentication telemetry |

| AlertEvidence | Evidence linked to Defender alerts |



These schemas form the foundation of Microsoft Defender advanced hunting and detection engineering.



---



\# Detection Translation From SOC Homelab



Existing detections built in the SOC home lab were translated into Microsoft Defender schema equivalents.



| Homelab Telemetry | Microsoft Schema |

|---|---|

| Sysmon Event ID 1 (Process Execution) | DeviceProcessEvents |

| Sysmon Network Events | DeviceNetworkEvents |

| Suricata IDS Alerts | DeviceNetworkEvents |

| Firewall Monitoring | AzureActivity / NSG Logs |

| Cloud Identity Monitoring | SigninLogs / AuditLogs |



This demonstrates how behavior-based detections can be ported between SIEM and XDR platforms.



---



\# Detection 1 — LOLBin Execution Monitoring



Attackers frequently abuse built-in Windows binaries known as Living-Off-The-Land Binaries (LOLBins).



Examples include:



\- certutil.exe

\- powershell.exe

\- bitsadmin.exe

\- mshta.exe



\### KQL Detection



```kql

DeviceProcessEvents

| where FileName in~ ("certutil.exe","powershell.exe","bitsadmin.exe","mshta.exe")

| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

| sort by Timestamp desc

```



---



\# Detection 2 — PowerShell Encoded Command Detection



Encoded PowerShell commands are frequently used for obfuscation and payload delivery.



\### Detection Logic



Identify PowerShell execution containing encoded command parameters.



\### KQL Query



```kql

DeviceProcessEvents

| where FileName =~ "powershell.exe"

| where ProcessCommandLine has\_any ("-enc","-encodedcommand")

| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

| sort by Timestamp desc

```



---



\# Detection 3 — Suspicious Parent-Child Process Relationships



Unusual process relationships can indicate malicious document execution or phishing payloads.



Examples:



\- winword.exe → powershell.exe

\- excel.exe → cmd.exe

\- outlook.exe → mshta.exe



\### KQL Query



```kql

DeviceProcessEvents

| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")

| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe")

| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine

| sort by Timestamp desc

```



---



\# Detection 4 — Hybrid Detection (Process + Network Correlation)



Advanced detection logic correlates endpoint activity with network telemetry.



\### Detection Logic



PowerShell encoded command followed by outbound network activity.



\### KQL Query



```kql

DeviceProcessEvents

| where FileName =~ "powershell.exe"

| where ProcessCommandLine has\_any ("-enc","-encodedcommand")

| join kind=inner (

&nbsp;   DeviceNetworkEvents

&nbsp;   | project DeviceName, RemoteIP, RemoteUrl, Timestamp

) on DeviceName

| project Timestamp, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemoteUrl

| sort by Timestamp desc

```



---



\# Detection 5 — Suspicious SIEM Hunting Activity



A real detection was implemented using Log Analytics query telemetry.



\### Data Source



```

LAQueryLogs

```



This table records queries executed in Log Analytics.



Monitoring SIEM queries can detect:



\- malicious insider activity

\- compromised analyst accounts

\- attacker reconnaissance within the SIEM



\### Detection Logic



Identify multiple suspicious hunting queries containing LOLBin or encoded PowerShell keywords within a short time window.



\### KQL Query



```kql

LAQueryLogs

| where TimeGenerated >= ago(24h)

| where RequestClientApp == "AppAnalytics"

| where QueryText has\_any ("certutil","powershell","mshta","bitsadmin","-enc","-encodedcommand")

| summarize SuspiciousQueryCount=count(), SampleQueries=make\_set(QueryText,3) by bin(TimeGenerated, 10m)

| where SuspiciousQueryCount >= 3

| sort by TimeGenerated desc

```



\### MITRE ATT\&CK Mapping



Tactic: Discovery  

Technique: T1087 – Account Discovery



---



\# Key Learning Outcomes



\- Learned the Microsoft Defender XDR telemetry model

\- Translated existing SOC detections into Microsoft schemas

\- Developed detection engineering skills using KQL

\- Implemented a real Sentinel detection using SIEM query telemetry

\- Practiced mapping detections to MITRE ATT\&CK



---



\# Conclusion



Day 3 demonstrated how behavior-based detections developed in a custom SOC home lab can be translated into Microsoft Sentinel and Microsoft Defender environments.



The exercise also highlighted the importance of schema understanding when migrating detection engineering logic between different security platforms.

