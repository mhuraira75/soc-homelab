\# File Integrity Monitoring (FIM) – Windows 11



\## Purpose

Enable and validate File Integrity Monitoring (FIM) on the Windows endpoint to detect unauthorized file changes.



FIM is a core Host-Based Intrusion Detection (HIDS) capability used in SOC environments.



---



\## Configuration Location

FIM configuration for Windows endpoints is defined locally on the agent.



\*\*Configuration File:\*\*

C:\\Program Files (x86)\\ossec-agent\\ossec.conf





---



\## FIM Configuration Added

The following directory was configured for real-time monitoring:



```xml

<directories realtime="yes">C:\\SOC-LAB</directories>







---



\## Why this file matters

You are demonstrating:

\- understanding of \*\*where detection logic lives\*\*

\- controlled testing

\- detection validation



This is \*\*real SOC work\*\*.



---



\# 3️⃣ `validation-notes.md`



👉 \*\*Purpose:\*\*  

This is your \*\*proof-of-work\*\* file — very important for recruiters.



\### Paste this entire content:



```markdown

\# Validation and Alert Verification – Day 4



\## Objective

Validate end-to-end telemetry flow from the Windows endpoint to the SIEM and confirm alert visibility.



---



\## Validation Methods



\### Dashboard Validation

\- Agent status confirmed as \*\*Active\*\*

\- Alerts visible in the Wazuh Dashboard

\- File Integrity Monitoring alert displayed correctly



---



\### SIEM Backend Validation

Alerts were verified directly on the SIEM backend to confirm ingestion and processing.



\*\*Alert file location:\*\*
/var/ossec/logs/alerts/alerts.json




Alerts were parsed into a human-readable format using `jq`.



---



\## Key Observations

\- Alerts are stored as structured JSON for performance and machine parsing.

\- The dashboard presents a visual abstraction of backend alert data.

\- Backend validation is essential for troubleshooting and investigation workflows.



---



\## Screenshots and Evidence

Supporting screenshots are stored in the `screenshots/` directory, including:

\- Agent status (Active)

\- File Integrity Monitoring alert

\- SIEM backend alert parsing



---



\## Conclusion

The Windows endpoint is fully integrated into the SIEM, generating actionable alerts that can be investigated through both the dashboard and backend logs.





