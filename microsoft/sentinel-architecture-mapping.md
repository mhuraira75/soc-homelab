\# Phase 5 — Day 1

\# Microsoft Sentinel Deployment, Detection Engineering \& Incident Lifecycle



\## Overview

Day 1 focused on deploying Microsoft Sentinel in a live Azure environment, configuring cloud telemetry ingestion, validating data flow, engineering a KQL detection, and completing a full detection-to-incident workflow inside the unified Microsoft Defender portal.



---



\## Environment Deployment



A Log Analytics Workspace was created and used as the storage/query layer for Sentinel:



\- \*\*Workspace:\*\* `sentinel-law`

\- \*\*Resource Group:\*\* `soc-sentinel-lab`

\- \*\*Region:\*\* UK South

\- \*\*Subscription:\*\* Azure subscription 1



Microsoft Sentinel was enabled on the `sentinel-law` workspace to establish the SIEM layer.



\*\*Architecture (high level):\*\*



Azure Subscription  

→ Log Analytics Workspace  

→ Microsoft Sentinel  

→ Microsoft Defender portal (unified SecOps experience)



---



\## Azure Activity Log Ingestion



Azure Activity logs are not automatically ingested into Sentinel. Subscription-level export was configured via:



`Monitor → Activity Log → Export Activity Logs`



A diagnostic setting was created to stream platform logs to the `sentinel-law` workspace. Key categories enabled included Administrative, Security, Policy, and ServiceHealth.



\*\*Ingestion pipeline:\*\*



Azure Subscription  

→ Azure Activity Logs  

→ Diagnostic Settings  

→ Log Analytics Workspace  

→ Microsoft Sentinel / Microsoft Defender



\*\*Operational note:\*\* initial streaming required an ingestion delay (~15–20 minutes). Activity logs did not backfill historical events.



---



\## Telemetry Generation \& Validation



To validate ingestion end-to-end, controlled administrative events were generated:



1\. Create a temporary resource group

2\. Delete the same resource group



After propagation, events were observed in the `AzureActivity` table, including:



\- `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE`

\- `Success`

\- Caller identity

\- Resource group name

\- Full resource identifier path



---



\## Detection Engineering (KQL)



A high-confidence detection was engineered to identify successful resource group deletions (destructive cloud administrative activity):



```kql

AzureActivity

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"

| where ActivityStatusValue == "Success"

| project TimeGenerated, Caller, ResourceGroup, \_ResourceId



This query isolates destructive actions and extracts investigation entities (time, actor, target).



\## Create/Delete Visibility Query

A consolidated query to list both create and delete operations:



AzureActivity

| where TimeGenerated > ago(24h)

| where OperationNameValue has\_any ("resourcegroups/write", "resourcegroups/delete")

| extend Action = case(

&nbsp;   OperationNameValue has "delete", "Delete",

&nbsp;   OperationNameValue has "write", "Create",

&nbsp;   "Other"

)

| project TimeGenerated, Action, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup, \_ResourceId

| sort by TimeGenerated desc



\## Unified Defender Portal Validation

The same AzureActivity telemetry was queried from the Microsoft Defender portal (Advanced Hunting), confirming unified SecOps visibility of Sentinel/Log Analytics tables through a single hunting surface.



\## Custom Detection Rule \& Incident Lifecycle

The validated KQL query was converted into a Custom Detection in the Defender portal:



* Category: Suspicious Activity
* Severity: High
* Schedule: 5 minutes
* Lookback: 20 minutes
* Trigger: results > 0
* Entity mapping: Caller → Account
* Recommended actions: documented to guide SOC triage and escalation decisions



To validate automation, a new test resource group was created and deleted. The detection triggered a High severity alert, which generated an incident in the Defender portal. The incident was reviewed, evidence validated, and the alert was confirmed as an intentional lab validation.



\## Key Observations

* Azure Activity ingestion requires subscription-level export to Log Analytics.
* Streaming does not backfill historical events.
* Initial export may take ~15–30 minutes to begin delivering logs.
* Unified Defender portal can query Sentinel/Log Analytics tables using Advanced Hunting.
* Entity mapping improves correlation and investigation fidelity.





