\# Wazuh SIEM Installation – SOC Deployment



\## Purpose

This document describes the deployment of Wazuh as the central SIEM platform for the SOC home lab.



The focus is on \*\*operational understanding\*\*, \*\*security considerations\*\*, and \*\*real-world SOC deployment practices\*\*, rather than command memorization.



---



\## Why Wazuh



Wazuh was selected as the SIEM platform for the following reasons:



\- Open-source and enterprise-aligned SIEM capabilities

\- Native support for Windows and Linux endpoints

\- Integrated log collection, alerting, and visualization

\- Strong alignment with SOC analyst workflows

\- Suitable for both learning and production-style deployments



---



\## Deployment Model



\- \*\*Deployment Type:\*\* All-in-One

\- \*\*Components Installed on Single Server:\*\*

&nbsp; - Wazuh Manager

&nbsp; - Wazuh Indexer

&nbsp; - Wazuh Dashboard



An all-in-one model is appropriate for a home lab environment while preserving the same logical separation of components used in enterprise deployments.



---



\## Core Components Explained



\### Wazuh Manager

\- Collects and analyzes logs from agents

\- Applies detection rules and decoders

\- Generates security alerts

\- Acts as the central analysis engine



---



\### Wazuh Indexer

\- Stores logs and alerts

\- Enables fast searching and correlation

\- Supports investigation workflows



---



\### Wazuh Dashboard

\- Web-based interface for SOC analysts

\- Used for alert triage and investigation

\- Accessible via HTTPS from the analyst workstation



---



\## Installation Approach



\- Used the official Wazuh installation script

\- Enabled automatic certificate generation

\- Followed vendor-recommended secure defaults

\- Performed installation on a fully updated system



Vendor-provided installation methods reduce misconfiguration risk and reflect real-world deployment practices.



---



\## Credential Handling During Installation



\- Administrative credentials were generated automatically by the installer

\- Credentials were captured once during initial setup

\- Stored securely in a password manager

\- Not stored on the SIEM server or in plaintext files



This aligns with SOC best practices for privileged credential handling.



---



\## Access and Security Model



\- \*\*Administrative Access:\*\* SSH to Ubuntu Server

\- \*\*SOC Analyst Access:\*\* Wazuh Dashboard (HTTPS)

\- \*\*Certificate-Based Security:\*\* Enabled by default

\- \*\*Separation of Duties:\*\* Backend administration separated from analysis access



This model mirrors enterprise SOC environments where analysts do not require direct server access.



---



\## Post-Installation Validation



After installation, the following checks were performed:



\- Verified Wazuh services were running

\- Confirmed dashboard accessibility

\- Validated secure HTTPS access

\- Established baseline system state prior to onboarding endpoints



---



\## Design Considerations



\- No graphical interface installed on the SIEM server

\- Minimal services enabled

\- Remote management via SSH only

\- Credentials isolated from the SIEM host



These choices reduce attack surface and support stable SOC operations.



---



\## Outcome



Wazuh SIEM is deployed and operational as the central SOC platform.



The system is ready for:

\- Endpoint agent onboarding

\- Log ingestion

\- Alert generation

\- SOC investigation workflows



