

---



\# 2) `endpoints/windows-11/sysmon-ingestion-validation.md`



```markdown

\# Sysmon Ingestion and Visibility Validation (Wazuh)



\## Objective

Validate end-to-end Sysmon telemetry ingestion from the Windows endpoint into the Wazuh SIEM and ensure the data is visible for analyst workflows (backend validation + dashboard view).



---



\## Data Path (End-to-End)

This validation confirms the following pipeline:



Windows Process Activity

→ Sysmon Event Channel (Microsoft-Windows-Sysmon/Operational)

→ Wazuh Windows Agent

→ Wazuh Manager (SIEM backend)

→ Wazuh Dashboard (analyst view)



---



\## Step 1: Confirm Sysmon Channel Exists (Windows)

The Sysmon channel was verified on the endpoint:



```powershell

wevtutil el | findstr /i sysmon



Expected output includes:

Microsoft-Windows-Sysmon/Operational





Wazuh agent configuration file:

C:\\Program Files (x86)\\ossec-agent\\ossec.conf



The Sysmon event channel was enabled by adding:

<localfile>

&nbsp; <location>Microsoft-Windows-Sysmon/Operational</location>

&nbsp; <log\_format>eventchannel</log\_format>

</localfile>



After changes, the agent service was restarted to apply configuration.

NET STOP WazuhSVC

NET START WazuhSVC





Example validation (Sysmon Process Create – Event ID 1):

sudo jq 'select(.agent.name=="WIN-ENDPOINT-01") | select(.data.win.system.providerName=="Microsoft-Windows-Sysmon") | .data.win.system.eventID' /var/ossec/logs/alerts/alerts.json | tail -n 10





Sysmon events were made visible in the Wazuh Dashboard using a targeted filter:



Search query used:



agent.name:"WIN-ENDPOINT-01" AND data.win.system.providerName:"Microsoft-Windows-Sysmon"







