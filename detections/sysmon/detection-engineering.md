\# Day 6 — Detection Engineering (Sysmon)



\## Objective

Build and validate a real-world Sysmon-based detection aligned with SOC workflows and MITRE ATT\&CK.



\## Detection Overview

\- Detection Name: PowerShell ExecutionPolicy Bypass

\- Rule ID: 100602

\- Severity: Level 10

\- Data Source: Sysmon (Event ID 1 – Process Create)

\- SIEM: Wazuh

\- Endpoint: Windows 11 VM



\## Threat Context

Attackers commonly use `-ExecutionPolicy Bypass` to disable PowerShell execution restrictions during post-exploitation and reconnaissance.



MITRE ATT\&CK:

\- T1059.001 – PowerShell

\- Tactic: Execution



\## Detection Logic

The detection triggers when:

\- A Sysmon Process Create event is observed

\- The process image is `powershell.exe`

\- The command line contains `ExecutionPolicy Bypass`

\- The executing user is NOT `NT AUTHORITY\\SYSTEM`



\## Wazuh Rule

```xml

<group name="day6,sysmon,powershell,">

&nbsp; <rule id="100602" level="10">

&nbsp;   <if\_group>sysmon\_event1</if\_group>

&nbsp;   <field name="win.eventdata.image" type="pcre2">\\\\powershell\\.exe</field>

&nbsp;   <field name="win.eventdata.commandLine" type="pcre2">(?i)ExecutionPolicy\\s+Bypass</field>

&nbsp;   <field name="win.eventdata.user" type="pcre2">(?i)^(?!NT AUTHORITY\\\\\\\\SYSTEM).\*</field>

&nbsp;   <description>PowerShell ExecutionPolicy Bypass (Sysmon EID 1)</description>

&nbsp;   <mitre>

&nbsp;     <id>T1059.001</id>

&nbsp;   </mitre>

&nbsp; </rule>

</group>



Validation



Backend validation performed using /var/ossec/logs/alerts/alerts.json



Alert confirmed with Rule ID 100602



Detection verified in Wazuh Dashboard with correct severity, MITRE mapping, and command-line context



Outcome



Successfully implemented and validated a production-style Sysmon detection, demonstrating the full detection engineering workflow:

telemetry → detection logic → tuning → backend validation → analyst view confirmation.







---



\# ✅ That’s it — no other files needed for Day 6



\### You do NOT need:

❌ a separate `day-6.md` at root  

❌ a generic “detection-engineering.md”  

❌ to document trial/error or debugging  



What you now have is:

\- \*\*Clean\*\*

\- \*\*Scalable\*\*

\- \*\*SOC-realistic\*\*

\- \*\*Interview-ready\*\*



---



\## Optional (recommended next)

If you want, next I can:

\- Review your final Markdown before you push

\- Give you \*\*exact Git commit messages\*\*

\- Start \*\*Day 7\*\* (second detection or incident report)



Just tell me what you want to do next 👌

::contentReference\[oaicite:0]{index=0}



