\# Phase 5 — Day 4  

\# Advanced KQL Correlation \& Threat Hunting



\## Overview



Day 4 focused on advanced KQL techniques used by SOC analysts for threat hunting and multi-source correlation inside the Microsoft security ecosystem.



The objective was to move beyond single-table detections and build \*\*behavior-based correlation logic\*\* across multiple telemetry sources. The lab followed a realistic SOC workflow: build hunting queries → validate patterns → correlate signals → refine into detection-ready logic.



\*\*Telemetry sources used (available in this lab):\*\*

\- AzureActivity (Azure control-plane activity)

\- LAQueryLogs (SIEM query telemetry)

\- SecurityAlert

\- SecurityIncident



\*\*Lab constraint:\*\* No Defender endpoint subscription, so the work focused on the tables above.



---



\## Environment



\*\*Platform:\*\* Microsoft Sentinel / Microsoft Defender unified portal  

\*\*Data:\*\* AzureActivity, LAQueryLogs, SecurityAlert, SecurityIncident  

\*\*Time windows used:\*\* 7d and 30d (depending on the query)



---



\## Step 1 — Telemetry Availability Verification



Before building correlations, table availability was validated to confirm what data could be used.



&nbsp;   let lookback = 30d;

&nbsp;   union withsource=TableName

&nbsp;       AzureActivity,

&nbsp;       SecurityAlert,

&nbsp;       SecurityIncident,

&nbsp;       LAQueryLogs,

&nbsp;       SigninLogs

&nbsp;   | where TimeGenerated >= ago(lookback)

&nbsp;   | summarize Rows=count(), Latest=max(TimeGenerated), Earliest=min(TimeGenerated) by TableName

&nbsp;   | order by Rows desc



\*\*Observed in this lab:\*\* The following tables had data:

\- AzureActivity

\- SecurityAlert

\- SecurityIncident

\- LAQueryLogs



---



\## Step 2 — Threat Hunting: Rare Azure Control-Plane Operations



Cloud attackers often perform \*\*rare or unusual infrastructure operations\*\* during post-compromise activity. This hunt identifies operations that occurred only a small number of times in the lookback window.



&nbsp;   AzureActivity

&nbsp;   | where TimeGenerated >= ago(7d)

&nbsp;   | extend

&nbsp;       Operation = tostring(OperationNameValue),

&nbsp;       CallerUPN = tostring(Caller),

&nbsp;       IP = tostring(CallerIpAddress)

&nbsp;   | summarize

&nbsp;       TotalEvents = count(),

&nbsp;       DistinctCallers = dcount(CallerUPN),

&nbsp;       DistinctIPs = dcount(IP),

&nbsp;       SampleCallers = make\_set(CallerUPN, 5),

&nbsp;       SampleIPs = make\_set(IP, 5),

&nbsp;       Latest = max(TimeGenerated)

&nbsp;     by Operation

&nbsp;   | where TotalEvents <= 3

&nbsp;   | project Latest, TotalEvents, Operation, DistinctCallers, SampleCallers, DistinctIPs, SampleIPs

&nbsp;   | order by TotalEvents asc



\*\*SOC relevance:\*\* Rare operations can indicate reconnaissance, experimentation, or malicious configuration changes.



\*\*KQL techniques used:\*\* summarize, count, dcount, make\_set, project



---



\## Step 3 — Time-Window Behavior Detection: Repeated Admin Actions



Attackers often perform \*\*multiple infrastructure actions in short bursts\*\*. This query detects repeated Azure operations by the same identity/IP within a defined time window.



&nbsp;   AzureActivity

&nbsp;   | where TimeGenerated >= ago(7d)

&nbsp;   | extend

&nbsp;       Operation = tostring(OperationNameValue),

&nbsp;       CallerUPN = tostring(Caller),

&nbsp;       IP = tostring(CallerIpAddress)

&nbsp;   | summarize

&nbsp;       OperationCount = count(),

&nbsp;       Operations = make\_set(Operation, 10)

&nbsp;     by CallerUPN, IP, bin(TimeGenerated, 30m)

&nbsp;   | where OperationCount >= 2

&nbsp;   | project TimeGenerated, CallerUPN, IP, OperationCount, Operations

&nbsp;   | order by OperationCount desc



\*\*Result in this lab:\*\* Returned rows (validated that time-window aggregation works in the environment).



\*\*SOC relevance:\*\* Compromised admin accounts, automation abuse, attacker post-access bursts.



\*\*KQL techniques used:\*\* bin(), summarize, count, make\_set, project



---



\## Step 4 — Hunt: Suspicious SIEM Query Activity (LAQueryLogs)



Attackers (or insiders) may explore SIEM coverage after access. This hunt counts queries referencing common attacker tooling terms.



&nbsp;   LAQueryLogs

&nbsp;   | where TimeGenerated >= ago(7d)

&nbsp;   | where QueryText has\_any ("certutil","powershell","mshta","bitsadmin","encodedcommand")

&nbsp;   | summarize SuspiciousQueryCount=count()



\*\*SOC relevance:\*\* Potential SIEM reconnaissance, unauthorized hunting, attacker attempting to learn detection coverage.



---



\## Step 5 — Cross-Table Correlation (Working Approach): Time-Window Join



Because identity/IP matching was not consistently available across LAQueryLogs fields in this lab view, correlation was engineered using \*\*time-window alignment\*\* (a valid SOC approach for multi-signal detection when direct joins are not reliable).



This query correlates:

\- Suspicious SIEM query bursts (LAQueryLogs)

\- Azure administrative activity (AzureActivity)

within the same 1-hour bin.



&nbsp;   LAQueryLogs

&nbsp;   | where TimeGenerated >= ago(30d)

&nbsp;   | where QueryText has\_any ("certutil","powershell","mshta","bitsadmin","encodedcommand")

&nbsp;   | summarize SuspQueryCount=count(), SampleQueries=make\_set(substring(QueryText,0,80), 5)

&nbsp;       by TimeBin = bin(TimeGenerated, 1h)

&nbsp;   | join kind=inner (

&nbsp;       AzureActivity

&nbsp;       | where TimeGenerated >= ago(30d)

&nbsp;       | extend Operation=tostring(OperationNameValue), Caller=tostring(Caller), IP=tostring(CallerIpAddress)

&nbsp;       | summarize AzureOpCount=count(), SampleOps=make\_set(Operation, 8), SampleCallers=make\_set(Caller, 5), SampleIPs=make\_set(IP, 5)

&nbsp;           by TimeBin = bin(TimeGenerated, 1h)

&nbsp;   ) on TimeBin

&nbsp;   | project TimeBin, SuspQueryCount, AzureOpCount, SampleOps, SampleCallers, SampleIPs, SampleQueries

&nbsp;   | order by TimeBin desc



\*\*Result in this lab:\*\* Returned rows, including an example window with \*\*SuspQueryCount = 9\*\* and \*\*AzureOpCount = 2\*\*.



\*\*SOC meaning:\*\* Two suspicious signals in close proximity:

\- SIEM hunting activity referencing attacker tools

\- Cloud control-plane operations occurring in the same time window



This combination can indicate:

\- post-compromise reconnaissance (attacker checking monitoring)

\- insider misuse (unauthorized hunting + admin actions)

\- early-stage cloud manipulation after log analysis



\*\*KQL techniques used:\*\* join, summarize, make\_set, bin, project



---



\## Step 6 — Detection Engineering: Make It “Rule-Ready” With Thresholds



This refines the correlation into detection logic by applying thresholds suitable for alerting.



Detection concept:

If suspicious SIEM hunting activity is high (e.g., >= 3 in an hour) AND Azure admin operations occur in the same hour, alert.



&nbsp;   LAQueryLogs

&nbsp;   | where TimeGenerated >= ago(7d)

&nbsp;   | where QueryText has\_any ("certutil","powershell","mshta","bitsadmin","encodedcommand")

&nbsp;   | summarize SuspiciousQueryCount=count(),

&nbsp;       SampleQueries=make\_set(substring(QueryText,0,80), 5)

&nbsp;       by TimeBin = bin(TimeGenerated, 1h)

&nbsp;   | join kind=inner (

&nbsp;       AzureActivity

&nbsp;       | where TimeGenerated >= ago(7d)

&nbsp;       | extend Operation=tostring(OperationNameValue), Caller=tostring(Caller)

&nbsp;       | summarize AzureOperationCount=count(),

&nbsp;           Operations=make\_set(Operation, 8),

&nbsp;           Callers=make\_set(Caller, 5)

&nbsp;           by TimeBin = bin(TimeGenerated, 1h)

&nbsp;   ) on TimeBin

&nbsp;   | where SuspiciousQueryCount >= 3

&nbsp;   | project

&nbsp;       DetectionTime = TimeBin,

&nbsp;       SuspiciousQueryCount,

&nbsp;       AzureOperationCount,

&nbsp;       Operations,

&nbsp;       Callers,

&nbsp;       SampleQueries

&nbsp;   | order by DetectionTime desc



\*\*Why this is a detection (not just correlation):\*\*

\- It has explicit conditions (thresholds) that define “alert-worthy” behavior.

\- It produces SOC-friendly output fields for triage (counts + samples + who + what).



---



\## MITRE ATT\&CK Mapping (Conceptual)



\*\*Primary tactic:\*\* TA0007 — Discovery  

Likely techniques (depending on query intent and operations observed):

\- T1087 — Account Discovery

\- T1083 — File and Directory Discovery



\*\*Secondary tactic:\*\* TA0005 — Defense Evasion  

Possible technique:

\- T1562 — Impair Defenses (if correlation includes disabling logging, policy changes, or security control modifications)



---



\## Key Skills Demonstrated



\- Advanced KQL operators: summarize, extend, project, make\_set, count, bin, join

\- Time-window behavior detections (burst analysis)

\- Cross-table correlation using time-binned joins

\- SOC threat hunting workflows in Microsoft telemetry

\- Converting hunts into detection-ready logic with thresholds and triage outputs



---



\## Outcome



Day 4 successfully demonstrated \*\*SOC-grade KQL correlation engineering\*\* using only available telemetry (no endpoint subscription). The lab produced a detection-ready correlation query showing suspicious SIEM hunting query bursts aligned with Azure administrative activity within the same time window.



---



\## Next: Phase 5 — Day 5



\*\*Interview + CV weaponization\*\*

\- Microsoft SOC storytelling (Sentinel + Defender portal workflow)

\- KQL correlation talking points (why bin + summarize + join)

\- Portfolio polishing: screenshots + concise “SOC outcome” narrative

\- Prepared interview answers: investigations, tuning, false positives, escalation

