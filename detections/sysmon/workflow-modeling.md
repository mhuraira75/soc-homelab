\# Day 21 — Detection Engineering: Multi-Stage Workflow Behaviour Modeling



\## Objective

Detect attacker-style workflows where high-intent PowerShell acts as an orchestrator launching multiple LOLBins and persistence mechanisms.



\## Threat Context

Modern attackers rarely rely on a single tool. Instead, they execute multi-stage workflows using legitimate binaries (LOLBins) to evade detection.



This detection models attacker intent rather than single tools.



\## Data Source

\- Sysmon Event ID 1 (Process Create)

\- Wazuh SIEM



\## MITRE ATT\&CK Mapping

\- T1059.001 — PowerShell

\- T1218 — System Binary Proxy Execution

\- T1053.005 — Scheduled Task



\## Detection Logic



\### Layer 1 — High Intent Launcher

Detect PowerShell executions using:

\- ExecutionPolicy Bypass

\- NoProfile

\- Hidden window

\- Encoded command



\### Layer 2 — Behaviour Stage

Detect child processes spawned by high-intent PowerShell:

\- certutil.exe

\- rundll32.exe

\- schtasks.exe



\## SOC Engineering Insight

Rather than detecting individual tools, this rule identifies orchestrated behaviour chains indicating attacker workflow progression.



\## Validation

Confirmed via simulated attacker workflow:

PowerShell (bypass) → certutil encode → rundll32 URL handler → schtasks persistence.



