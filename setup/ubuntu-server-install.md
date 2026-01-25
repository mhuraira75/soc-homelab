\# Ubuntu Server Installation – SOC SIEM Backend



\## Purpose

This document describes the installation and baseline configuration of Ubuntu Server used as the backend operating system for the SOC SIEM platform.



The goal is to align with \*\*real-world SOC and enterprise server practices\*\*, not desktop or lab-only setups.



---



\## Why Ubuntu Server (CLI-Only)



Ubuntu Server was selected instead of a desktop operating system for the following reasons:



\- Reduced attack surface (no graphical desktop)

\- Lower CPU and memory usage

\- Greater stability for long-running services

\- Alignment with enterprise SOC backend environments

\- Improved suitability for SSH-based administration



In production SOCs, SIEM platforms are almost always deployed on server operating systems without a GUI.



---



\## Virtual Machine Preparation



\- \*\*Hypervisor:\*\* VMware Workstation

\- \*\*VM Type:\*\* Dedicated SIEM server

\- \*\*Resources:\*\* Allocated to support log indexing and analysis

\- \*\*Networking:\*\* NAT (DHCP) for controlled internet access and isolation



A dedicated VM ensures separation of SOC infrastructure from analyst workstations and endpoints.



---



\## Installation Approach



\- \*\*Installation Media:\*\* Official Ubuntu Server ISO

\- \*\*Installation Type:\*\* Standard Ubuntu Server (non-minimal)

\- \*\*Disk Configuration:\*\* Full disk usage with default layout

\- \*\*Package Selection:\*\* Minimal base system



The default server installation provides a stable and secure baseline without unnecessary services.



---



\## Network Configuration



\- \*\*Interface Configuration:\*\* DHCP

\- \*\*Rationale:\*\*

&nbsp; - Simplicity for home lab environments

&nbsp; - Predictable connectivity

&nbsp; - Sufficient isolation via NAT



Static IP configuration is not required at this stage and can be introduced later if needed.



---



\## User and Host Configuration



\- \*\*Hostname:\*\* wazuh-siem

\- \*\*Administrative User:\*\* Dedicated non-root user

\- \*\*Access Model:\*\* Privilege escalation via sudo



This approach avoids direct root usage and follows least-privilege principles commonly used in enterprise environments.



---



\## SSH Configuration



\- \*\*OpenSSH Server:\*\* Installed during OS installation

\- \*\*Purpose:\*\*

&nbsp; - Secure remote administration

&nbsp; - Elimination of hypervisor console dependency

&nbsp; - Alignment with SOC operational workflows



SSH is used as the primary method for managing the SIEM server from the analyst workstation.



---



\## Post-Installation Baseline Checks



After installation, the following baseline checks were performed:



\- Network connectivity verified

\- SSH service status confirmed

\- System packages updated

\- System rebooted to ensure clean service startup



These steps establish a known-good baseline prior to deploying SOC tooling.



---



\## Security Considerations



\- No graphical desktop installed

\- No unnecessary services enabled

\- Remote access restricted to SSH

\- Administrative actions performed using sudo

\- System prepared before installing SIEM components



This ensures the SIEM backend starts from a hardened and predictable state.



---



\## Outcome



Ubuntu Server is installed and operational as a dedicated SOC SIEM backend.



The system is:

\- Accessible via SSH

\- Network-connected

\- Updated and stable

\- Ready for SIEM installation and monitoring workloads



