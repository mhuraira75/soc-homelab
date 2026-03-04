\# Phase 5 — Microsoft SOC Translation Blueprint (No Subscription Plan)

\## Day 2 — KQL Translation \& Data Model Mastery



---



\# Overview



Day 2 focused on developing \*\*Microsoft Sentinel KQL detection engineering skills\*\* using Azure control-plane telemetry available in a no-subscription Azure environment.



Because this lab intentionally avoids paid Microsoft Defender integrations, endpoint telemetry tables such as:



\- DeviceProcessEvents  

\- DeviceNetworkEvents  

\- IdentityLogonEvents  



were \*\*not available\*\*.



Instead, the lab used \*\*AzureActivity logs\*\*, which provide Azure control-plane activity telemetry. This still allows practice of the most important SOC analyst skills when working with Microsoft Sentinel:



\- Understanding Microsoft Sentinel data models  

\- Analyzing Azure Activity logs  

\- Discovering operational telemetry  

\- Writing KQL detection queries  

\- Performing behavior-based detections  

\- Correlating events using KQL  



The goal of the session was to \*\*translate SOC detection engineering techniques into Microsoft Sentinel KQL workflows\*\*.



---



\# Environment



Platform: Microsoft Sentinel  

Workspace: sentinel-law  

Resource Group: soc-sentinel-lab  

Region: UK South  

Primary Data Source: Azure Activity Logs  



Available tables discovered in the workspace:



\- AzureActivity  

\- SecurityAlert  

\- SecurityIncident  

\- LAQueryLogs  

\- Usage  



Among these tables, \*\*AzureActivity\*\* provides the most relevant telemetry for security monitoring in this lab environment.



---



\# Step 1 — Workspace Table Inventory



The first step was identifying which telemetry tables were present in the workspace.



Query used:



search \*

| where TimeGenerated >= ago(24h)

| summarize Events=count() by $table

| sort by Events desc



Tables observed:



\- AzureActivity  

\- SecurityAlert  

\- SecurityIncident  

\- LAQueryLogs  

\- Usage  



This confirmed that \*\*AzureActivity logs were available for detection engineering exercises\*\*.



---



\# Step 2 — AzureActivity Schema Inspection



To understand what fields were available for detection logic, sample events were inspected.



Query used:



AzureActivity

| take 10



Important fields identified:



TimeGenerated – Timestamp of activity  

Caller – Identity performing the operation  

OperationNameValue – Azure operation executed  

ActivityStatusValue – Result of the operation  

ResourceGroup – Target resource group  

ResourceProviderValue – Azure service provider  

\_ResourceId – Unique identifier of the resource  



These fields form the \*\*foundation of cloud activity monitoring within Microsoft Sentinel\*\*.



---



\# Step 3 — Operation Discovery



Next, the operations occurring in the Azure environment were identified.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| summarize Count=count() by OperationNameValue

| sort by Count desc

| take 25



Operations discovered:



MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE  

MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE  



Meaning of these operations:



RESOURCEGROUPS/WRITE  

Creation or modification of Azure resource groups.



RESOURCEGROUPS/DELETE  

Deletion of Azure resource groups.



These operations are important from a SOC perspective because they may indicate:



\- Infrastructure deployment  

\- Administrative configuration changes  

\- Automation scripts  

\- Potential attacker cleanup activity  



---



\# Detection Engineering



The following detection queries were engineered using AzureActivity telemetry.



---



\# Detection 1 — Resource Group Deletion Monitoring



Purpose: Detect destructive operations within Azure infrastructure.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"

| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, ResourceGroup, ResourceProviderValue, \_ResourceId

| order by TimeGenerated desc



This detection highlights \*\*resource group deletion events\*\*, which may indicate destructive activity or attacker cleanup.



---



\# Detection 2 — Burst Deletion Behavior



Purpose: Detect multiple deletion operations occurring in a short time window.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"

| summarize DeleteCount=count() by Caller, bin(TimeGenerated, 10m)

| where DeleteCount >= 2

| order by TimeGenerated desc



Detection logic:



Multiple resource groups deleted within a 10-minute window.



Possible implications:



\- Destructive scripts  

\- Malicious insider activity  

\- Attacker cleanup operations  



---



\# Detection 3 — Repeated Resource Creation Activity



Purpose: Detect repeated Azure operations performed by the same identity within short time intervals.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| summarize OperationCount=count() by Caller, OperationNameValue, bin(TimeGenerated, 5m)

| where OperationCount >= 2

| order by TimeGenerated desc



Observed operation:



MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE



Possible explanations:



\- Automated infrastructure deployment  

\- Infrastructure scripts  

\- Rapid administrative actions  



---



\# Detection 4 — Resource Creation Burst Detection



Purpose: Identify bursts of resource group creation or modification.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE"

| summarize WriteCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Caller, bin(TimeGenerated, 5m)

| where WriteCount >= 2

| order by LastSeen desc



This detection highlights \*\*multiple resource group changes performed by the same user within a short time period\*\*.



---



\# Detection 5 — Correlation Detection (WRITE → DELETE)



Purpose: Detect when a resource group is created or modified and then deleted shortly afterward.



Query used:



(

AzureActivity

| where TimeGenerated >= ago(24h)

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE"

| project Caller, ResourceGroup, WriteTime=TimeGenerated

)

| join kind=inner

(

AzureActivity

| where TimeGenerated >= ago(24h)

| where OperationNameValue =~ "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"

| project Caller, ResourceGroup, DeleteTime=TimeGenerated

)

on Caller, ResourceGroup

| where DeleteTime between (WriteTime .. WriteTime + 30m)

| project Caller, ResourceGroup, WriteTime, DeleteTime

| order by DeleteTime desc



Detection logic:



Resource group created or modified  

→ deleted within 30 minutes.



Possible interpretations:



\- Attacker testing infrastructure then removing it  

\- Malicious cleanup activity  

\- Destructive automation scripts  



---



\# Detection 6 — Rapid Control Plane Activity



Purpose: Detect multiple Azure operations occurring within a very short time window.



Query used:



AzureActivity

| where TimeGenerated >= ago(24h)

| summarize OperationCount=count() by Caller, bin(TimeGenerated, 1m)

| where OperationCount >= 2

| order by TimeGenerated desc



Detection logic:



Multiple Azure control-plane operations executed within one minute.



Possible causes:



\- Automation scripts  

\- Deployment pipelines  

\- Suspicious high-frequency activity  



---



\# KQL Techniques Practiced



The following KQL techniques were used during the lab:



where – Filter specific telemetry  

summarize – Aggregate activity data  

count() – Measure event frequency  

bin() – Create time windows for behavior detection  

join – Correlate related events  

order by – Prioritize investigation results  



These techniques represent the \*\*core KQL skills used by SOC analysts working with Microsoft Sentinel\*\*.



---



\# Investigation Outcome



All activity observed during this lab originated from the legitimate user account:



muhammadhuraira177@outlook.com



Actions performed included:



\- Creating resource groups  

\- Modifying resource groups  

\- Deleting resource groups  

\- Executing multiple Azure control-plane operations  



These activities were generated intentionally as part of the lab exercises.



No malicious activity was identified.



---



\# Key Learning Outcomes



This lab reinforced several Microsoft Sentinel SOC concepts:



\- Understanding Azure control-plane telemetry  

\- Building detection queries in Microsoft Sentinel  

\- Identifying behavior-based patterns in cloud activity  

\- Correlating events using KQL joins  

\- Investigating Azure infrastructure operations  



These skills directly align with real \*\*SOC Analyst responsibilities when working with Microsoft Sentinel\*\*.



---



\# Next Phase



Phase 5 — Day 3 will focus on:



\- Advanced KQL correlation techniques  

\- Threat hunting queries in Microsoft Sentinel  

\- Detection engineering patterns used in SOC environments  

\- Investigation workflows using Microsoft Sentinel telemetry

