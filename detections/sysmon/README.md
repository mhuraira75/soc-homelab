# Sysmon Detections

This directory contains custom Sysmon-based detections developed in a SOC-style home lab using Wazuh.

All detections in this folder are:

- Built from real endpoint telemetry
- Aligned with MITRE ATT&CK
- Validated via backend logs (`alerts.json`)
- Verified in the Wazuh Dashboard
- Tuned to reduce false positives

---

## Available Detections

- **Day 6:** PowerShell ExecutionPolicy Bypass  
  - MITRE: T1059.001

- **Day 7:** PowerShell Web Request (Invoke-WebRequest / iwr / wget) with SYSTEM noise tuning — Rule `100603`
  - `powershell-webrequest-system-tuning.md`
