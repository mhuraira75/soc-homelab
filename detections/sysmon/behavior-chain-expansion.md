\# Behavior Chain Expansion — PowerShell → LOLBins



\## Objective



Move beyond single-tool detections and detect attacker workflow patterns using parent-child process relationships and command-line context.



This stage focuses on identifying behavior chains where PowerShell acts as an execution orchestrator spawning Living-Off-The-Land Binaries (LOLBins).



---



\## SOC Engineering Mindset



Attackers rarely execute isolated tools. Real-world intrusions often follow chained workflows:



1\. PowerShell or scripting host initiates execution.

2\. LOLBins are launched for defense evasion or proxy execution.

3\. Command-line indicators reveal execution intent.



Detecting relationships between processes provides stronger signals than matching tools individually.



---



\## Environment



\- Wazuh SIEM deployed on Ubuntu Server

\- Windows 11 endpoint (WIN-ENDPOINT-01)

\- Sysmon installed (Event ID 1 — Process Create)

\- Logs ingested via windows\_eventchannel decoder



---



\## Telemetry Validation



Real telemetry confirmed in archives.json:



Parent Process:

\- powershell.exe



Child Processes:

\- mshta.exe

\- certutil.exe

\- rundll32.exe



Example observed execution:



PowerShell → mshta.exe (vbscript execution)



---



\## Detection Engineering



\### Rule 200820 — Behavior Chain Detection (Base)



Detects workflow patterns where:



\- Parent process = powershell.exe

\- Child process = common LOLBins:



&nbsp; - certutil.exe

&nbsp; - mshta.exe

&nbsp; - rundll32.exe

&nbsp; - regsvr32.exe



Purpose:



Identify suspicious execution chains rather than individual binaries.



---



\### Rule 200821 — High Confidence Behavior Chain



Extends Rule 200820 by adding suspicious command-line indicators:



Examples:



\- vbscript:

\- javascript:

\- http:// or https://

\- -enc or -EncodedCommand

\- scrobj.dll or scriptlet patterns



Purpose:



Increase detection confidence by combining behavior relationships with execution intent signals.



---



\## MITRE ATT\&CK Mapping



\- T1059.001 — Command and Scripting Interpreter: PowerShell

\- T1218 — System Binary Proxy Execution



---



\## Validation



\- Rules successfully loaded into Wazuh

\- Alerts confirmed in alerts.json

\- Parent-child relationships verified via Sysmon telemetry

\- Behavior chain detection functioning as expected



---



\## SOC Analyst Learning Outcome



\- Transition from tool-based detection to behavior-based detection engineering

\- Understanding of attacker workflow modeling

\- Use of parent-child relationships for higher-fidelity alerts

\- Severity layering using command-line enrichment



---



\## Future Improvements



\- Add allowlisting for known administrative automation workflows

\- Expand LOLBin coverage

\- Introduce multi-stage correlation logic across sequential events





