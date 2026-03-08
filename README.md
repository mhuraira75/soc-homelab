# SOC Home Lab – Detection Engineering & SOC Investigation Lab

This directory documents the practical detection engineering and investigation work performed inside my SOC home lab environment.

The lab is designed to simulate real-world Security Operations Center (SOC) workflows by combining multiple telemetry sources, SIEM platforms, and investigation techniques.

Each markdown file in this directory represents a documented phase of the lab where detection logic, investigation workflows, and monitoring capabilities were developed and validated.

The focus of this lab is **operational SOC capability**, not just tool deployment.

---

## 🎯 Objectives

- Develop behaviour-based security detections
- Simulate SOC investigation workflows
- Practice SIEM detection engineering
- Investigate authentication and system activity logs
- Correlate multi-layer telemetry sources
- Document investigations and detection logic
- Build SOC-style monitoring dashboards
- Maintain documentation-first operational discipline

---

## 🛠️ Lab Environment

Primary Infrastructure

- **SIEM Platform:** Wazuh SIEM
- **Secondary SIEM Platform:** Splunk Enterprise
- **Cloud SIEM Platform:** Microsoft Sentinel
- **Operating System:** Ubuntu Server 22.04 LTS
- **Endpoint OS:** Windows 11
- **Hypervisor:** VMware Workstation Pro
- **Access Method:** SSH + Web dashboards

Security Telemetry Sources

- Windows Security Logs
- Sysmon endpoint telemetry
- Suricata IDS network telemetry
- UFW firewall logs
- Linux authentication logs (`/var/log/auth.log`)
- Cloud identity activity logs
- AzureActivity telemetry
- LAQueryLogs (Microsoft cloud analytics logs)

Security Tooling

- Wazuh SIEM
- Splunk Enterprise
- Microsoft Sentinel
- Microsoft Defender Portal
- Suricata IDS
- Sysmon
- Nessus Essentials

---

## 🔐 SOC Practices Implemented

The lab environment follows several operational security practices commonly used in SOC environments:

- Dedicated SIEM server deployment
- CLI-based server administration
- SSH-only remote access
- Minimal OS footprint to reduce attack surface
- Separation of monitoring and endpoint systems
- Controlled telemetry generation for detection testing
- Documentation-first workflow for investigations
- Structured incident-style reporting

---

## 📂 Repository Structure

Each markdown file in this directory represents a documented lab phase covering a specific SOC capability area.

The documentation includes:

- Detection engineering logic
- Investigation queries
- SOC investigation workflows
- Security telemetry analysis
- Monitoring dashboard creation
- Incident-style reporting

The files follow the progression of the SOC home lab development.

---

# Lab Phases Documented

## Phase 1 — Endpoint Detection Engineering

Focus: Behaviour-based endpoint detections using Windows telemetry.

Activities included:

- PowerShell behaviour detections
- Encoded command detection
- LOLBins monitoring
- Parent-child process analysis
- Persistence and privilege escalation behaviour
- MITRE ATT&CK aligned detection modelling

---

## Phase 2 — Hybrid Detection Engineering (Endpoint + Network IDS)

Expanded the lab to include network telemetry correlation.

Implemented:

- Suricata IDS integration
- DNS and TLS telemetry monitoring
- Endpoint + network detection correlation
- Hybrid detection engineering logic

---

## Phase 3 — Firewall Detection Engineering

Introduced perimeter monitoring capabilities.

Implemented:

- UFW firewall telemetry ingestion
- Detection of repeated blocked connection attempts
- Port-based detection logic
- Scan-like behaviour detection
- Firewall burst detection modelling

---

## Phase 4 — Cloud Identity Detection Engineering

Expanded monitoring into cloud identity activity.

Implemented:

- GitHub telemetry ingestion
- Cloud identity event monitoring
- JSON-based log parsing
- Detection logic for cloud activity events
- Identity-centric monitoring workflows

---

## Phase 5 — Microsoft SOC Detection Engineering

Translated detection engineering logic into Microsoft-native SOC environments.

Implemented:

- Microsoft Sentinel deployment
- AzureActivity telemetry ingestion
- KQL threat hunting
- Detection rule creation
- Cross-table correlation using KQL
- Defender incident investigation workflow

---

## Phase 6 — SOC Operational Skills Mini-Labs

Focused on real SOC analyst operational workflows.

Simulated activities included:

- Phishing email investigation
- IOC extraction and reputation analysis
- SOAR automation pipeline modelling
- SOC incident investigation lifecycle
- Evidence collection and escalation decisions

---

## Phase 7 — Linux Investigation & Vulnerability Management

Expanded the lab into Linux monitoring and vulnerability assessment.

Activities included:

Linux security investigations:

- SSH authentication failure analysis
- Authentication anomaly investigation
- Sudo privilege escalation monitoring
- User account activity analysis

Vulnerability management:

- Nessus vulnerability scanning
- CVE and CVSS analysis
- Security posture evaluation

---

## Phase 8 — Splunk SOC Detection & Investigation

Introduced Splunk as a second SIEM platform for detection engineering and investigations.

Implemented:

Splunk deployment and ingestion:

- Splunk Enterprise installation
- Log ingestion from `/var/log/auth.log`
- Authentication telemetry monitoring

Detection engineering using SPL:

- Regular expression field extraction
- SSH brute-force detection queries
- Sudo activity monitoring
- Authentication abuse detection logic

SOC investigation workflows:

- Attacker source IP analysis
- Targeted username analysis
- Authentication attack timeline reconstruction
- Correlation of authentication failures and privilege activity

Security monitoring dashboards:

- SSH authentication failure visualization
- Attacker IP activity panels
- Targeted user monitoring
- Privileged command activity monitoring
- SOC monitoring dashboard panels

---

## 📊 Documentation Style

Each lab phase follows a structured documentation format including:

- Environment setup
- Telemetry validation
- Detection logic
- Investigation methodology
- SPL / KQL queries
- SOC workflow simulation
- Outcome and analysis

This structure mirrors how detection engineering and investigation work is documented inside enterprise SOC teams.

---

## 🚧 Lab Status

The SOC home lab currently includes:

- Multi-layer telemetry collection
- Multi-SIEM investigation capability
- Behaviour-based detection engineering
- Security monitoring dashboards
- SOC investigation workflow simulations
- Vulnerability management capability

The environment continues to serve as a platform for practicing real SOC operations and security monitoring techniques.

---

## 📌 Disclaimer

This lab environment is built strictly for **educational and defensive security research purposes**.

All attack simulations and detections are performed within an isolated lab environment.
