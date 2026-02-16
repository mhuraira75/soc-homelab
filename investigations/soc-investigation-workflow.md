\# SOC Investigation Workflow (Behaviour Chain Analysis \& Alert Triage)



\## Objective



Transition from detection engineering mindset into SOC analyst investigation workflow by performing structured alert triage, behaviour chaining analysis, and contextual risk evaluation using real telemetry from the SOC home lab environment.



---



\## Environment



\- Wazuh SIEM (Manager / Indexer / Dashboard)

\- Ubuntu Server VM

\- Windows 11 Endpoint (WIN-ENDPOINT-01)

\- Sysmon telemetry enabled

\- Custom detection rules from previous lab phases



---



\## Investigation Focus



This session focused on SOC Level 1 analyst workflow:



\- Alert triage methodology

\- Behaviour chain reconstruction

\- Process lineage analysis

\- Context enrichment

\- Risk classification (Benign vs Suspicious vs Malicious)



---



\## Behaviour Chain Observed



Simulated attacker-style activity using PowerShell:



1\. PowerShell ExecutionPolicy bypass



powershell.exe -ExecutionPolicy Bypass



2\. Discovery commands executed:



\- whoami.exe

\- ipconfig.exe

\- net user

\- net localgroup administrators

\- netstat -ano



---



\## Process Lineage Analysis



Observed parent-child relationships:



powershell.exe → native Windows discovery tools







Key learning:



\- Individual commands may appear benign.

\- Sequential chaining creates strong attacker-like pattern.



---



\## SOC Triage Methodology Applied



Fast triage checklist:



1\. User context (who executed activity)

2\. Parent process relationship

3\. Command-line intent

4\. Behaviour chain correlation

5\. Environmental context validation



---



\## Risk Classification



Activity classified as:



Suspicious Behaviour — Confirmed Benign (Authorised Lab Activity)





Reasoning:



\- ExecutionPolicy bypass increases risk.

\- Sequential discovery commands match early-stage attacker reconnaissance.

\- Activity attributed to known interactive lab user.



---



\## Key SOC Analyst Insights



\- Alerts must be analysed as behaviour chains rather than isolated events.

\- Parent-child relationships provide critical context.

\- Office applications spawning PowerShell would significantly increase risk.

\- Obfuscated PowerShell commands (EncodedCommand) represent higher threat level.



---



\## Detection Engineering Insight



Analysis identified opportunity for future improvement:



\- Correlate multiple discovery events into single high-confidence behaviour-chain detection.



---



\## Skills Practiced



\- SOC alert prioritisation

\- Incident narrative building

\- Risk-based escalation decision-making

\- Process lineage evaluation

\- Context-driven investigation



---



\## MITRE ATT\&CK Mapping



\- T1059.001 — PowerShell Execution

\- T1082 — System Information Discovery

\- T1016 — Network Discovery

\- T1087 — Account Discovery

\- T1049 — Network Connection Discovery



---



\## Outcome



Successfully transitioned from detection engineering workflow into SOC investigation mindset aligned with SOC-ready analyst practices.



