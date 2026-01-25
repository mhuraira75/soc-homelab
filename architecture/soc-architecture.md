\# SOC Home Lab Architecture



\## Overview

This document describes the architecture of a SOC-style home lab designed to simulate real-world Security Operations Center (SOC) environments.



The architecture prioritizes:

\- Secure server deployment

\- Clear separation of roles

\- Realistic SOC access patterns

\- Documentation-first operations



---



\## Core Components



\### 1. SIEM Server (WAZUH-SIEM)

\- \*\*Platform:\*\* Wazuh (All-in-One)

\- \*\*Operating System:\*\* Ubuntu Server 22.04 LTS (CLI-only)

\- \*\*Role:\*\*

&nbsp; - Log ingestion

&nbsp; - Alert generation

&nbsp; - Security event analysis

\- \*\*Installed Components:\*\*

&nbsp; - Wazuh Manager

&nbsp; - Wazuh Indexer

&nbsp; - Wazuh Dashboard



The SIEM server is deployed without a graphical interface to reduce attack surface and align with enterprise SOC backend practices.



---



\### 2. Analyst Workstation (Windows 11 Host)

\- \*\*Operating System:\*\* Windows 11

\- \*\*Role:\*\*

&nbsp; - SOC analysis via web dashboard

&nbsp; - Secure remote administration via SSH

&nbsp; - Documentation and reporting

\- \*\*Tools Used:\*\*

&nbsp; - Web browser (SIEM dashboard access)

&nbsp; - SSH client (Windows OpenSSH)

&nbsp; - Password manager (credential storage)

&nbsp; - Git/GitHub (documentation and version control)



The analyst workstation never stores SIEM credentials in plaintext or on the server itself.



---



\### 3. Endpoint Systems (Planned / In Progress)

\- \*\*Primary Endpoint:\*\* Windows 11

\- \*\*Future Endpoints:\*\*

&nbsp; - Linux-based systems

\- \*\*Role:\*\*

&nbsp; - Generate logs and security telemetry

&nbsp; - Simulate user and system activity

&nbsp; - Support detection and investigation scenarios



Endpoints are monitored using Wazuh agents and configured to forward relevant security logs to the SIEM.



---



\## Access Model



\### Administrative Access

\- \*\*Method:\*\* SSH

\- \*\*Target:\*\* Ubuntu Server (WAZUH-SIEM)

\- \*\*Purpose:\*\*

&nbsp; - System administration

&nbsp; - Service management

&nbsp; - Configuration changes



Direct console access via the hypervisor is avoided for daily operations.



---



\### SOC Analyst Access

\- \*\*Method:\*\* HTTPS (Web Browser)

\- \*\*Target:\*\* Wazuh Dashboard

\- \*\*Purpose:\*\*

&nbsp; - Alert triage

&nbsp; - Log analysis

&nbsp; - Investigation workflows



This separation mirrors real SOC environments where analysts do not have direct server access.



---



\## Network Architecture

\- \*\*Virtualization Platform:\*\* VMware Workstation

\- \*\*Network Mode:\*\* NAT (DHCP)

\- \*\*Characteristics:\*\*

&nbsp; - Internet access for updates

&nbsp; - Isolation from the home LAN

&nbsp; - Predictable internal IP addressing



This setup balances security, simplicity, and realism for a SOC lab environment.



---



\## Security Practices Implemented

\- Dedicated SIEM server with minimal OS footprint

\- No GUI installed on backend systems

\- SSH-based remote administration

\- Secure credential storage using a password manager

\- Separation of system access and analyst access

\- Documentation of baseline architecture and decisions



---



\## Design Rationale

This architecture reflects common patterns found in enterprise SOCs:

\- Backend systems are hardened and CLI-based

\- Analysts interact with SIEM platforms through dashboards

\- Credential hygiene and access control are prioritized

\- Documentation supports repeatability and auditability



---



\## Future Enhancements

\- Endpoint agent onboarding and telemetry expansion

\- Detection rule tuning and alert optimization

\- Incident-style investigation reports

\- Role-based access separation within the SIEM



