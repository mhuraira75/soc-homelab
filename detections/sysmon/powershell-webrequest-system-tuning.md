# Day 7 — Sysmon Detection: PowerShell Web Request (IWR/Wget) with SYSTEM Noise Tuning

## Objective
Detect suspicious PowerShell web request activity (commonly used for payload download or staging) using Sysmon Process Create events (Event ID 1), while tuning out legitimate SYSTEM-level noise to reduce false positives.

This detection focuses on identifying user-driven PowerShell activity that leverages built-in web request functionality such as:
- Invoke-WebRequest
- iwr
- wget (PowerShell alias)

---

## Detection Overview

| Item | Value |
|-----|------|
| SIEM | Wazuh |
| Log Source | Sysmon |
| Sysmon Event ID | 1 (Process Create) |
| Rule ID | 100603 |
| Severity | High (Level 10) |
| Platform | Windows 11 |
| User Scope | Non-SYSTEM users |

---

## Threat Context

PowerShell is frequently abused by attackers to:
- Download payloads
- Stage second-stage malware
- Retrieve scripts or tooling
- Communicate with external infrastructure

Using native PowerShell web request commands allows attackers to blend in with legitimate administrative activity, making behavioral detection critical.

---

## Detection Logic

The rule triggers when **all** of the following conditions are met:

1. Sysmon Process Create event (Event ID 1)
2. Process image ends with `powershell.exe`
3. Command line contains:
   - `Invoke-WebRequest`
   - `iwr`
   - `wget`
4. Execution is **not** performed by the SYSTEM account

---

## Wazuh Rule

```xml
<group name="local,sysmon,day7">

  <rule id="100603" level="10">
    <if_group>sysmon_event1</if_group>

    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">1</field>

    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\b(invoke-webrequest|iwr|wget)\b</field>

    <!-- Noise reduction -->
    <field name="win.eventdata.user" type="pcre2">(?i)^(?!.*SYSTEM).*$</field>

    <description>
      PowerShell web request command executed (possible download or execution)
    </description>

    <mitre>
      <id>T1059.001</id>
      <id>T1105</id>
    </mitre>
  </rule>

</group>
