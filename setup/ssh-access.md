\# SSH Access Model – SOC SIEM Server



\## Purpose

This document describes how secure remote access to the SOC SIEM server is implemented using SSH.



The access model reflects \*\*real-world SOC and enterprise practices\*\*, where backend systems are managed remotely and not through direct console interaction.



---



\## Why SSH Is Used



SSH is the primary access method for SOC backend systems because it provides:



\- Encrypted communication

\- Strong authentication mechanisms

\- Auditability of access

\- Compatibility with automation and tooling

\- Reduced reliance on physical or hypervisor console access



In production SOC environments, direct console access is typically restricted or disabled.



---



\## Access Roles



\### Administrative Access

\- \*\*Method:\*\* SSH

\- \*\*User Type:\*\* Dedicated administrative user

\- \*\*Purpose:\*\*

&nbsp; - System administration

&nbsp; - Service management

&nbsp; - Configuration changes

&nbsp; - SIEM maintenance



Administrative access is limited to tasks that require system-level privileges.



---



\### SOC Analyst Access

\- \*\*Method:\*\* Web browser (HTTPS)

\- \*\*Target:\*\* Wazuh Dashboard

\- \*\*Purpose:\*\*

&nbsp; - Alert triage

&nbsp; - Log analysis

&nbsp; - Investigation workflows



SOC analysts do not require direct SSH access to the SIEM server.



---



\## SSH Configuration Overview



\- OpenSSH server installed during OS installation

\- Default secure configuration used

\- Access controlled via user accounts and sudo

\- Root login avoided for routine operations



This configuration supports least-privilege principles and reduces risk.



---



\## Analyst Workstation Access



\- SSH connections initiated from the analyst workstation (Windows 11)

\- Native Windows OpenSSH client used

\- Credentials not stored in plaintext

\- Sessions established only when administrative access is required



This mirrors how SOC analysts and engineers manage infrastructure in enterprise environments.



---



\## Security Considerations



\- SSH used only for administration, not analysis

\- Credentials stored in a password manager

\- Hypervisor console access avoided for daily operations

\- Clear separation between system administration and SOC analysis



---



\## Outcome



The SIEM server can be securely managed remotely using SSH, while SOC analysis is performed through the SIEM dashboard.



This access model supports secure, auditable, and scalable SOC operations.





