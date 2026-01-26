\# Validation and Alert Verification – Windows 11 Endpoint (Day 4)



\## Objective

Validate end-to-end telemetry flow from the Windows 11 endpoint to the Wazuh SIEM and confirm that security alerts are correctly generated, ingested, and observable.



This validation ensures the endpoint onboarding was successful and operationally reliable.



---



\## Validation Scope

The following components were validated:

\- Agent-to-manager connectivity

\- Windows Security event ingestion

\- File Integrity Monitoring (FIM) alert generation

\- Alert visibility via dashboard and SIEM backend



---



\## Agent Connectivity Validation



\### Dashboard Verification

\- The Windows endpoint agent appears in the Wazuh Dashboard.

\- Agent status is displayed as \*\*Active\*\*.

\- Heartbeat and last check-in timestamps are updating correctly.



This confirms successful enrollment and ongoing communication.



---



\### SIEM Backend Verification

Agent status was additionally verified from the SIEM backend to confirm operational state independent of the dashboard.



The agent was visible and active from the SIEM host.



This backend verification helps distinguish ingestion or connectivity issues from dashboard-only issues.



---



\## Log and Alert Validation



\### Windows Event Ingestion

Windows Security events were generated on the endpoint (logon activity) and observed arriving at the SIEM.



This confirms that endpoint telemetry is being forwarded and processed correctly.



---



\### File Integrity Monitoring (FIM) Alert

A controlled file modification test was performed on the monitored directory.



Results:

\- A File Integrity Monitoring alert was generated.

\- The alert included correct file path and endpoint identification.

\- Alert timestamps matched the test activity.



---



\## Backend Alert Inspection



Alerts were validated directly on the SIEM backend using the following file:
/var/ossec/logs/alerts/alerts.json




Alerts were parsed into a readable format using `jq` to inspect:

\- Rule metadata

\- Agent information

\- File modification details

\- Event timestamps



This confirms alerts are correctly generated at the SIEM engine level.



---



\## Dashboard vs Backend Observation



\- The Wazuh Dashboard provides a visual and analyst-friendly view of alerts.

\- The SIEM backend stores alerts in structured JSON format for performance and automation.

\- Backend inspection is essential for troubleshooting ingestion, parsing, or detection logic issues.



---



\## Evidence

Screenshots supporting this validation are stored in the `screenshots/` directory, including:

\- Agent status (Active)

\- File Integrity Monitoring alert in the dashboard

\- Backend alert parsing output



---



\## Conclusion

The Windows 11 endpoint onboarding was successfully validated.



The endpoint is fully integrated into the SIEM and capable of generating actionable security alerts that can be investigated using both the dashboard and backend logs, aligning with real-world SOC workflows.







