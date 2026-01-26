\# Windows 11 – Wazuh Agent Onboarding



\## Objective

Onboard a Windows 11 endpoint into the Wazuh SIEM and establish reliable agent-to-manager communication.



This step marks the transition from SIEM setup to active SOC operations.



---



\## Endpoint Details

\- \*\*Operating System:\*\* Windows 11

\- \*\*Deployment Type:\*\* Virtual Machine

\- \*\*Hypervisor:\*\* VMware Workstation Pro

\- \*\*Role:\*\* Endpoint generating security telemetry



---



\## SIEM Details

\- \*\*SIEM Platform:\*\* Wazuh (All-in-One)

\- \*\*SIEM OS:\*\* Ubuntu Server 22.04 LTS

\- \*\*Manager Role:\*\* Log ingestion, alerting, analysis



---



\## Onboarding Method

Agent deployment was performed using the Wazuh Dashboard agent deployment workflow.



This method ensures:

\- Correct manager address configuration

\- Secure agent enrollment

\- Consistency with enterprise SOC practices



---



\## Installation Steps

1\. Generated Windows agent deployment command from the Wazuh Dashboard.

2\. Executed the PowerShell installation command on the Windows 11 endpoint with administrative privileges.

3\. Started the Wazuh agent service (`WazuhSVC`).

4\. Verified successful service startup without errors.



---



\## Connectivity Validation

Agent connectivity was validated using:

\- Wazuh Dashboard agent status

\- SIEM backend agent listing



The endpoint successfully registered and transitioned to an \*\*Active\*\* state.



---



\## Outcome

The Windows 11 endpoint is successfully onboarded and capable of sending security telemetry to the SIEM.



