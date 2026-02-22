\# PHASE 4 — Cloud Detection Engineering (Identity + Behaviour + Hybrid Correlation)

\## DAY 1 — Cloud Telemetry Foundation (REAL Microsoft Entra ID / Azure AD)



\### Objective (Day 1)

\- Understand cloud identity telemetry structure (Entra Sign-in logs)

\- Map detection-relevant fields (identity, source IP, auth result, device/session context, Conditional Access, MFA requirement)

\- Establish baseline understanding before writing detections (NO rules today)



---



\## Environment

\- Wazuh SIEM (Manager / Indexer / Dashboard)

\- Windows 11 endpoint with Sysmon

\- Suricata IDS integrated

\- Firewall telemetry integrated (UFW)

\- Cloud identity telemetry source: Microsoft Entra ID (Azure AD)



---



\## What we did (Lab Work)



\### A) Created JSON ingest path on Wazuh Manager

\*\*Wazuh Manager (Linux):\*\*

```bash

sudo mkdir -p /var/log/cloud\_identity

sudo touch /var/log/cloud\_identity/identity.json



Added localfile JSON reader

File: /var/ossec/etc/ossec.conf



<localfile>

&nbsp; <log\_format>json</log\_format>

&nbsp; <location>/var/log/cloud\_identity/identity.json</location>

</localfile>



Restarted:

sudo systemctl restart wazuh-manager

sudo systemctl status wazuh-manager --no-pager



\### B) Switched to real-world telemetry (Microsoft Entra ID)



* Created new Microsoft account (previous tenant blocked due to inactivity)



* Accessed Entra portal



* Navigated: Entra → Monitoring \& health → Sign-in logs



* Generated real sign-in via tenant-scoped Azure Portal login:

https://portal.azure.com/<tenant-domain>



Exported sign-in logs as JSON from Entra portal.



\### C) Uploaded exported Entra JSON to Wazuh Manager



Uploaded to:

/home/socadmin/socadmin/entra\_logs.json



Extracted first event and appended to identity log as NDJSON (1 JSON object per line):



sudo jq -c '.\[0]' /home/socadmin/socadmin/entra\_logs.json | sudo tee -a /var/log/cloud\_identity/identity.json >/dev/null



\## Verification (Wazuh archives ingestion)



Confirmed Entra event present in archives.json using correlationId:

019c833d-1bd4-76dc-8239-ef2b19afeb67



Example match showed:



* full\_log contains Entra JSON



* decoded fields available under .data



* source location: /var/log/cloud\_identity/identity.json



\## Field Mapping (Detection-Relevant Fields)



Extracted key fields from the real event:



Output:

time=2026-02-22T02:46:26Z user=muhammadhuraira177@outlook.com

&nbsp;app=Azure Portal ip=86.143.172.58 client=Browser result=0 ca=notApplied country=GB os=Windows10 browser=Edge 145.0.0 auth\_req=multiFactorAuthentication



Fields mapped:



* user identity: .data.userPrincipalName



* login source IP: .data.ipAddress



* app: .data.appDisplayName



* auth result: .data.status.errorCode + .data.status.failureReason



* device context: .data.deviceDetail.operatingSystem, .data.deviceDetail.browser



* session context: .data.clientAppUsed, .data.isInteractive, .data.sessionId



* conditional access status: .data.conditionalAccessStatus



* authentication requirement: .data.authenticationRequirement



* correlation/tracking: .data.correlationId



* location: .data.location.countryOrRegion, .data.location.city



\## Baseline Notes 



* Entra sign-in logs are not real-time (observed ~4–5 min delay).



* Real identity telemetry now flows into Wazuh and is queryable via .data.\*.



* Ready for Day 2: behaviour detections (failed bursts, MFA anomalies, new geo/device, impossible travel patterns, privilege changes).
