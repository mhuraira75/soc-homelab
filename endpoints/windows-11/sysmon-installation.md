\# Sysmon Installation – Windows 11 Endpoint



\## Objective

Enhance Windows endpoint telemetry by installing Sysmon (Sysinternals) and applying a curated configuration to improve visibility for SOC investigations (process creation, command-line context, and related endpoint activity).



---



\## Why Sysmon

Default Windows logs provide strong authentication and policy auditing, but often lack the detail required for rapid investigations (e.g., process lineage and command-line arguments). Sysmon adds high-fidelity endpoint telemetry commonly used in real SOC environments.



---



\## Tools and Components

\- \*\*Endpoint:\*\* Windows 11 (VMware VM)

\- \*\*Telemetry Tool:\*\* Sysmon (Microsoft Sysinternals)

\- \*\*SIEM:\*\* Wazuh (Manager + Dashboard)

\- \*\*Collector:\*\* Wazuh Windows Agent



---



\## Installation Location

Sysmon was staged in a dedicated directory to keep tooling organized and to simplify command execution and documentation:



C:\\Sysmon





---



\## Sysmon Configuration

A community-validated Sysmon configuration was used to balance visibility and noise, aligned with common SOC practices.



Config file stored as:



C:\\Sysmon\\sysmonconfig.xml





---



\## Installation Commands (PowerShell – Admin)



\### Change to Sysmon directory

```powershell

cd C:\\Sysmon





Install Sysmon with configuration

.\\Sysmon64.exe -accepteula -i sysmonconfig.xml






