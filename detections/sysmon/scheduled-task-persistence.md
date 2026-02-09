\# Day 10 — Detection Engineering: Scheduled Task Persistence (Sysmon EID 1)



\## Objective



Detect persistence techniques using Windows Scheduled Tasks created via `schtasks.exe`, leveraging Sysmon Event ID 1 telemetry in Wazuh.



This detection uses layered rule design to reduce noise while highlighting high-risk behaviour.



---



\## Threat Context



Scheduled Tasks are commonly abused by attackers to establish persistence or execute payloads at predefined intervals.



Advantages for attackers:



\- Reliable execution mechanism

\- Can run with SYSTEM privileges

\- Blends with legitimate administrative activity



---



\## Data Source



\- Log Source: Sysmon (Microsoft-Windows-Sysmon/Operational)

\- Event ID: 1 (Process Create)

\- Wazuh Decoder: windows\_eventchannel

\- Agent: WIN-ENDPOINT-01



---



\## MITRE ATT\&CK Mapping



\- T1053.005 — Scheduled Task/Job: Scheduled Task



---



\## Detection Logic



\### Rule 200606 — Base Detection (Telemetry Visibility)



Detects:



\- schtasks.exe execution

\- command line containing `/create`



Purpose:



\- Maintain awareness of persistence creation activity.

\- Lower severity to avoid alert fatigue.



---



\### Rule 200607 — Behaviour-Based High Signal Detection



Detects:



\- Scheduled task creation initiated from suspicious parent processes:



&nbsp; - powershell.exe

&nbsp; - cmd.exe

&nbsp; - wscript.exe

&nbsp; - cscript.exe

&nbsp; - mshta.exe

&nbsp; - rundll32.exe



Purpose:



\- Identify script-based persistence commonly used by attackers.



---



\### Rule 200608 — High-Risk Execution Path Detection



Detects:



\- Scheduled tasks executing binaries from user-writable locations:



&nbsp; - Downloads

&nbsp; - AppData

&nbsp; - Temp

&nbsp; - Desktop

&nbsp; - Public



Purpose:



\- Highlight high-probability malicious persistence techniques.



---



\## Validation Steps



1\. Created scheduled task using:

schtasks /create /tn "SOC-LAB-TestTask" /sc minute /mo 5 /tr "C:\\Windows\\System32\\calc.exe" /ru SYSTEM /f





2\. Confirmed telemetry:



\- Sysmon Event Viewer

\- Wazuh archives.json ingestion



3\. Verified alerts:



\- Rule 200606 triggered (baseline visibility)

\- Rule 200607 triggered when launched via PowerShell

\- Rule 200608 triggered when executing from Downloads path



---



\## SOC Engineering Notes



\- Parent-child rule chaining used for tuning.

\- Detection prioritizes behavioural indicators rather than simple command matching.

\- Severity levels adjusted to reduce analyst fatigue while preserving visibility.



---



\## Lessons Learned



\- Always validate telemetry ingestion before writing rules.

\- Behavioural context (parent process + execution path) greatly improves detection quality.

\- Layered detections align with real-world SOC practices.





