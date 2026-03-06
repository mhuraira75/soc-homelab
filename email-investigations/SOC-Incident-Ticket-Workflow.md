\# SOC Operational Skills Mini-Lab — Day 3  

\# SOC Incident Ticket Workflow Simulation (Alert → Triage → Investigation → Resolution)



\## Overview



Day 3 of the SOC Operational Skills Mini-Lab focused on simulating a \*\*real Security Operations Center (SOC) analyst workflow\*\* from detection to case resolution.



The objective was to practice the \*\*full SOC incident handling lifecycle\*\* using the existing \*\*Wazuh SIEM and Windows endpoint telemetry (Sysmon logs)\*\*.



The workflow simulated how a Tier-1 SOC analyst handles an alert by performing:



\- Alert triage

\- Log investigation

\- Event correlation

\- Evidence collection

\- Incident documentation

\- Escalation decision making

\- Final incident closure



This lab replicates the \*\*practical operational workflow performed in enterprise SOC environments\*\*.



---



\# Lab Environment



\*\*SIEM Platform\*\*



Wazuh SIEM



\*\*Endpoint Monitoring\*\*



Sysmon deployed on Windows endpoint



\*\*Endpoint Host\*\*



WIN-ENDPOINT-01



\*\*Endpoint IP\*\*



192.168.72.129



\*\*Operating System\*\*



Windows



\*\*Log Source\*\*



Microsoft Sysmon



---



\# Attack Simulation



To generate realistic SOC alerts, a simulated authentication scenario was created on the Windows endpoint.



The following command was executed multiple times to simulate credential usage attempts:

runas /user:.\\FakeUser cmd





The command attempts to launch a command prompt under another user account using the Windows \*\*RunAs utility\*\*.



Multiple executions were intentionally performed to simulate repeated credential activity.



---



\# Detection



Wazuh detected the activity through \*\*Sysmon Process Creation logs (Event ID 1)\*\*.



\### Detection Rule



Rule ID: 200702



Description: Sysmon Process Create detected



Severity Level: 3 (Informational)



\### Event Type



Sysmon Event ID 1 — Process Creation



\### Detected Process

C:\\Windows\\System32\\runas.exe





\### Command Line

runas /user:.\\FakeUser cmd





\### Parent Process

C:\\Windows\\System32\\cmd.exe





\### Execution User

DESKTOP-ON8B91Q\\socuser





---



\# Initial SOC Alert Triage



During triage, the analyst extracted key indicators from the alert:



\- Host generating the alert

\- Executed process

\- Command line arguments

\- Parent process

\- User account responsible for execution

\- Frequency of occurrence



Approximately \*\*10 identical execution events\*\* were observed within a short timeframe.



Repeated execution of \*\*runas.exe\*\* may indicate:



\- Credential misuse

\- Privilege escalation attempts

\- Password guessing attempts

\- Administrative activity



Because credential abuse tools are often used during attacker privilege escalation, the alert required further investigation.



---



\# Investigation Process



The following investigation steps were performed inside the Wazuh SIEM dashboard:



\### 1. Event Pivoting



Logs were filtered using the keyword:

FakeUser





This allowed identification of all related RunAs execution events.



\### 2. Event Correlation



Multiple alerts were identified containing identical attributes:



\- Same process (`runas.exe`)

\- Same command line

\- Same parent process (`cmd.exe`)

\- Same initiating user (`socuser`)



\### 3. Behavior Analysis



All events originated from the same endpoint and same logged-in user.



No additional suspicious activity was observed during the investigation window.



Specifically, analysts confirmed the absence of:



\- Privilege escalation attempts

\- Credential dumping activity

\- Lateral movement indicators

\- Suspicious child processes



---



\# Evidence Collected



\### Process Execution

Process: C:\\Windows\\System32\\runas.exe

CommandLine: runas /user:.\\FakeUser cmd

Event Source: Sysmon

Event ID: 1





\### Parent Process

Parent Process: C:\\Windows\\System32\\cmd.exe

Parent User: DESKTOP-ON8B91Q\\socuser





\### Activity Frequency

Observed Attempts: ~10 executions

Time Window: Few minutes

Pattern: Repeated identical command execution





\### Host Information

Hostname: WIN-ENDPOINT-01

IP Address: 192.168.72.129

Operating System: Windows





---



\# SOC Analyst Assessment



The observed activity involved repeated execution of the Windows \*\*RunAs utility\*\*, which is commonly used for administrative tasks but may also indicate credential abuse.



However, several factors indicated benign behavior:



\- The account \*\*FakeUser\*\* does not correspond to a legitimate system account.

\- All executions originated from the same logged-in user.

\- No additional malicious indicators were observed.

\- The activity occurred in a controlled lab environment.



Based on the available evidence, the activity was assessed as \*\*authorized testing activity\*\*.



---



\# SOC Escalation Decision



If this activity occurred in a \*\*production enterprise environment\*\*, the appropriate Tier-1 SOC action would be:



\*\*Escalate the incident to Tier-2 analysts for validation.\*\*



Reason for escalation:



\- Multiple credential execution attempts

\- Use of RunAs utility

\- Potential credential abuse indicator



SOC Tier-1 analysts typically escalate such cases to ensure no unauthorized credential activity is occurring.



---



\# Recommended Actions



If observed in a corporate environment:



1\. Contact the endpoint owner to verify the activity.

2\. Confirm whether the RunAs execution was authorized.

3\. Monitor the endpoint for additional authentication anomalies.

4\. Review account authentication logs for suspicious behavior.



---



\# Incident Outcome



\*\*Incident Classification\*\*



Benign / Authorized Testing



\*\*Incident Status\*\*



Closed



\*\*Escalation\*\*



Not required in the lab environment.



---



\# Skills Demonstrated



This lab demonstrates practical SOC analyst skills including:



\- SIEM alert triage

\- Windows event investigation

\- Process execution analysis

\- Event correlation

\- Incident documentation

\- Escalation decision making

\- SOC workflow simulation



---



\# Conclusion



This exercise simulated a real SOC analyst workflow using Wazuh SIEM and Sysmon endpoint telemetry.



By generating realistic endpoint activity and performing a structured investigation, the lab demonstrated how analysts move from \*\*alert detection to incident closure\*\*.



Hands-on incident simulations like this help develop the operational thinking required for \*\*Tier-1 SOC analyst roles\*\*, where rapid triage, accurate investigation, and proper escalation decisions are critical to effective security monitoring.

