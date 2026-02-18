\# SOC Investigation Case — LOLBin Download via Certutil



\## Summary

During SOC alert triage, a behaviour-based detection identified certutil performing an HTTP download spawned by PowerShell.



\## Environment

\- Wazuh SIEM

\- Sysmon telemetry

\- Windows 11 endpoint



\## Detection

Rule ID: 200805  

Technique: Certutil HTTP(S) download



\## Timeline

06:14:10 — explorer.exe → powershell.exe (interactive execution)  

06:14:36 — powershell.exe → certutil.exe download initiated  

06:20:15 — repeat execution observed  



\## Artifact Analysis

File:

C:\\Users\\Public\\day25\_test.txt



SHA256:

FB91D75A6BB430787A61B0AEC5E374F580030F2878E1613EAB5CA6310F7BBB9A



Content:

Example Domain HTML test page.



\## Supporting Alerts

Rule 92213 triggered on PowerShell temp policy test scripts.

Validated as benign expected behaviour.



\## MITRE ATT\&CK Mapping

\- T1105 — Ingress Tool Transfer

\- T1059.001 — PowerShell



\## Analyst Assessment

Behaviour resembles attacker tradecraft but confirmed as controlled lab testing.



\## Final Disposition

Benign Positive (High-risk technique).



\## Detection Improvements

\- Suppress \_\_PSScriptPolicyTest temp file alerts.

\- Maintain certutil detection for LOLBin monitoring.



