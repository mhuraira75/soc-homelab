# Day 8 — Detection Engineering: Encoded PowerShell (Sysmon Event ID 1)

---

## Objective

Develop and validate a custom Wazuh detection rule to identify PowerShell executions using encoded commands (`-EncodedCommand` / `-enc`) based on Sysmon Event ID 1 telemetry.

The goal of this lab is to simulate attacker behavior, engineer a detection aligned with MITRE ATT&CK, and validate the alert lifecycle from endpoint execution to SIEM alert generation.

---

## Threat Context

Attackers frequently use encoded PowerShell commands to:

- Obfuscate malicious payloads
- Evade simple signature-based detections
- Hide command-line intent
- Execute staged payloads

Encoded commands are commonly seen in:

- Initial access payloads
- Living-off-the-land attacks
- Malware execution chains
- Post-exploitation frameworks

---

## Data Source

- Endpoint OS: Windows 11 VM
- Log Source: Sysmon
- Channel: Microsoft-Windows-Sysmon/Operational
- Event ID: 1 (Process Creation)
- Decoder: `windows_eventchannel`
- SIEM Platform: Wazuh

---

## MITRE ATT&CK Mapping

- **T1059.001 — Command and Scripting Interpreter: PowerShell**

---

## Detection Strategy

Instead of creating a detection from scratch, this rule extends an existing built-in Wazuh detection:

- Parent rule: **92057**
- Description: PowerShell process executing Base64 encoded command

Custom detection logic:

- Process image ends with `powershell.exe`
- Command line contains:
  - `-enc`
  - OR `-EncodedCommand`
- Noise reduction applied:
  - Exclude executions from `NT AUTHORITY\SYSTEM`
  - Exclude Wazuh agent parent process

This approach demonstrates detection chaining using `<if_sid>` to reduce false positives and reuse validated detection logic.

---

## Final Detection Rule (local_rules.xml)

Rule ID used:

- Custom detection: **200604**

```xml
<group name="day8,powershell">

  <rule id="200604" level="10">
    <if_sid>92057</if_sid>

    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s(-enc|-encodedcommand)\s</field>

    <field name="win.eventdata.user" type="pcre2">(?i)^(?!NT AUTHORITY\\\\SYSTEM).*</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)^(?!.*\\\\ossec-agent\\\\wazuh-agent\.exe).*</field>

    <description>
    Day8: Encoded PowerShell detected (custom child of 92057: non-SYSTEM, non-agent parent)
    </description>

    <mitre>
      <id>T1059.001</id>
    </mitre>

  </rule>

</group>

esting Performed
Test Command Executed on Windows Endpoint
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA

Verification Steps

Confirmed detection through:

1. Real-time alert monitoring
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered -E '"id":"200604"|"id":"92057"'

2. Wazuh Dashboard

Alert observed in Security Events.

Rule ID 200604 triggered successfully.

3. Raw telemetry validation

Checked archives.log to confirm Sysmon EID 1 ingestion

Results

Custom rule 200604 successfully triggered.

Detection visible in Wazuh dashboard.

Alert pipeline validated end-to-end:

Endpoint execution

Log ingestion

Rule matching

Alert generation


Lessons Learned

Custom detections should leverage existing rule chains where possible.

Rule IDs must:

Be unique

Be integers

Maximum 6 digits

Live agent events are more reliable than isolated wazuh-logtest validation.

Detection engineering requires iterative troubleshooting of:

XML structure

Rule inheritance

Decoder matching

Field names

Skills Practiced

Detection engineering

Wazuh rule development

Sysmon telemetry analysis

MITRE ATT&CK mapping

SOC alert validation workflow

Troubleshooting SIEM rule loading errors