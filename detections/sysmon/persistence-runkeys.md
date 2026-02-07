\# Day 9 — Persistence Detection: Registry Run Keys (Sysmon EID 13)



\## Objective

Detect Windows persistence attempts via Registry Run keys by chaining a custom Wazuh rule to the default Sysmon EID 13 rule, then tuning to focus on suspicious launchers.



\## Environment

\- Wazuh SIEM: Ubuntu Server VM (Manager)

\- Endpoint: Windows 11 (Wazuh Agent)

\- Telemetry: Sysmon -> EventChannel -> Wazuh

\- Validation: alerts.json + Wazuh Dashboard



\## MITRE ATT\&CK

\- T1547.001 — Registry Run Keys / Startup Folder



\## Attack Simulation (Telemetry Generation)

\### Create persistence-style Run key

```powershell

reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdaterTest" /t REG\_SZ /d "powershell.exe -nop -w hidden -c calc.exe" /f





\## Cleanup

reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdaterTest" /f



\## Evidence (Observed Telemetry)

Sysmon Event ID 13 was generated and ingested by Wazuh.



Key fields observed in alerts.json / dashboard:



* Image: C:\\WINDOWS\\system32\\reg.exe
* TargetObject: ...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterTest
* Details: powershell.exe -nop -w hidden -c calc.exe



Default Wazuh rule observed:



* Rule ID 92302 — Run key modified via reg.exe (Sysmon EID 13)



\## Detection Engineering

\### Approach

* Use <if\_sid>92302</if\_sid> as the parent rule (stable parsing already done by Wazuh).
* Add child logic to categorize this as persistence and reduce noise.





\## Final Custom Rule (local\_rules.xml)

<group name="sysmon,windows,persistence,">



&nbsp; <rule id="200605" level="12">

&nbsp;   <if\_sid>92302</if\_sid>



&nbsp;   <!-- Avoid fragile backslash matching; focus on stable keywords -->

&nbsp;   <field name="win.eventdata.targetObject" type="pcre2">CurrentVersion.\*Run</field>



&nbsp;   <!-- Tuning: suspicious launchers commonly used for persistence -->

&nbsp;   <field name="win.eventdata.details" type="pcre2">

&nbsp;     (powershell\\.exe|cmd\\.exe|wscript\\.exe|cscript\\.exe|mshta\\.exe|rundll32\\.exe)

&nbsp;   </field>



&nbsp;   <description>Persistence via Registry Run Key with suspicious launcher (Sysmon EID 13)</description>



&nbsp;   <mitre>

&nbsp;     <id>T1547.001</id>

&nbsp;   </mitre>

&nbsp; </rule>



</group>





\## Validation

* Confirmed Sysmon EID 13 appears in Wazuh.
* Confirmed custom rule 200605 fires in:

1. /var/ossec/logs/alerts/alerts.json
2. Wazuh Dashboard

* Confirmed tuned description is displayed:

1. “Persistence via Registry Run Key with suspicious launcher (Sysmon EID 13)”



\## Notes

Run keys are used by legitimate software, so the detection was tuned to focus on suspicious launchers (PowerShell/cmd/script hosts/LOLBins) commonly used by attackers for persistence.



