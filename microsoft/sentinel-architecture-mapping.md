\# Phase 5 — Day 1  

\# Microsoft Sentinel Architecture \& Azure Activity Detection



---



\## Overview



Day 1 focused on deploying Microsoft Sentinel in a live Azure environment, configuring cloud telemetry ingestion, validating log flow, and engineering a production-style KQL detection aligned with real SOC operations.



This phase translated prior detection engineering experience (Wazuh-based lab) into Microsoft’s cloud-native SIEM architecture.



---



\## Environment Setup



\### Log Analytics Workspace



A Log Analytics Workspace was created:



\- \*\*Name:\*\* `sentinel-law`

\- \*\*Resource Group:\*\* `soc-sentinel-lab`

\- \*\*Region:\*\* UK South

\- \*\*Subscription:\*\* Azure subscription 1



This workspace serves as the log storage and query engine for Microsoft Sentinel.



---



\### Microsoft Sentinel Enablement



Microsoft Sentinel was enabled on the `sentinel-law` workspace.



Architecturally:



Azure Subscription  

→ Log Analytics Workspace  

→ Microsoft Sentinel (SIEM layer)



Sentinel provides:



\- Log ingestion management  

\- KQL-based analytics  

\- Detection rule engine  

\- Incident management workflows  



---



\## Azure Activity Log Ingestion



Azure Activity logs are not automatically streamed to Sentinel. Subscription-level diagnostic export must be configured.



Path used:

Monitor → Activity Log → Export Activity Logs





A diagnostic setting was created to stream logs to the `sentinel-law` workspace.



Enabled categories included:



\- Administrative

\- Security

\- Policy

\- ServiceHealth

\- Alert

\- Recommendation

\- Autoscale

\- ResourceHealth



This established the ingestion pipeline:



Azure Subscription  

→ Activity Log  

→ Diagnostic Settings  

→ Log Analytics Workspace  

→ Microsoft Sentinel  



---



\## Telemetry Generation \& Validation



To validate ingestion, controlled administrative actions were performed:



1\. Created a temporary resource group  

2\. Deleted the same resource group  



After an ingestion delay (~15–20 minutes), records appeared in the `AzureActivity` table.



\### Example Observed Event



\- \*\*Operation:\*\* `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE`

\- \*\*Status:\*\* Success

\- \*\*Caller:\*\* Authenticated Azure user

\- \*\*Target:\*\* Resource Group

\- \*\*Resource ID:\*\* Full subscription path



This confirmed successful end-to-end ingestion.



---



\## Detection Engineering (KQL)



A high-confidence detection was engineered to identify successful resource group deletions.



```kql

AzureActivity

| where TimeGenerated > ago(24h)

| where OperationNameValue has\_any ("resourcegroups/write", "resourcegroups/delete")

| project 

&nbsp;   TimeGenerated,

&nbsp;   OperationNameValue,

&nbsp;   ActivityStatusValue,

&nbsp;   Caller,

&nbsp;   ResourceGroup,

&nbsp;   \_ResourceId

| sort by TimeGenerated desc





\## Detection Logic



* Filters destructive cloud administrative action
* Ensures operation succeeded
* Extracts investigation entities:

1. Time
2. Actor
3. Target resource
4. Resource ID



This mirrors real SOC detection design for destructive cloud behavior.





\## Architectural Mapping to SOC Home Lab

**Wazuh-Based Lab	               Microsoft Sentinel Equivalent**

Sysmon ingestion	       AzureActivity / Log tables

Custom rules	               KQL analytics

archives.json	               Log Analytics tables

Alert workflow	               Unified Defender / Sentinel workflow



Core detection principles remain consistent across platforms; only tooling and schema differ.





\## Key Technical Observations



* Azure Activity logs require subscription-level export.
* Ingestion does not backfill historical events.
* Initial streaming may take 15–30 minutes.
* Unified Defender portal experience affects rule creation workflows.
* KQL-based detection engineering translates directly from traditional SIEM logic.





\## Outcome



By the end of Day 1:



* Microsoft Sentinel deployed
* Azure Activity ingestion configured and validated
* Live administrative telemetry generated
* Production-style cloud detection engineered
* Unified Microsoft SecOps architecture understood



This phase demonstrates practical Microsoft SIEM deployment and cloud detection engineering capability aligned with modern SOC environments.



