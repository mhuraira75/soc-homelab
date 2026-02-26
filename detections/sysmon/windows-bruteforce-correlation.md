\# 🔐 Windows Brute Force Detection (Wazuh Correlation Rule)



\## 📌 Overview



This project demonstrates behaviour-based brute force detection using Wazuh SIEM and Windows Security logs.



Instead of alerting on every failed login, this detection:



\- Triggers only after \*\*5 failed logon attempts\*\*

\- Requires attempts within \*\*60 seconds\*\*

\- Correlates based on:

&nbsp; - Same target username

&nbsp; - Same source IP address

\- Reduces alert fatigue

\- Models attacker behaviour instead of single events



---



\## 🖥️ Log Source



\*\*Windows Security Event Log\*\*



\- Event ID: `4625`

\- Description: \*An account failed to log on\*

\- Wazuh Rule ID Observed: `60122`

\- Decoder: `windows\_eventchannel`



\### Key Fields Used



```json

win.eventdata.targetUserName

win.eventdata.ipAddress

win.system.eventID



\## Detection Strategy

A single failed login attempt is not considered a brute force attack.



Brute force detection requires identifying a pattern of repeated authentication failures targeting the same account within a short timeframe.



Correlation logic implemented:



* frequency="5"
* timeframe="60"
* if\_matched\_sid
* same\_field



\## Custom Correlation Rule

\### File Location

/var/ossec/etc/rules/local\_rules.xml



\### Rule

<rule id="110501" level="10" frequency="5" timeframe="60">

&nbsp; <if\_matched\_sid>60122</if\_matched\_sid>

&nbsp; <same\_field>win.eventdata.targetUserName</same\_field>

&nbsp; <description>

&nbsp;   Brute Force Detected: 5 failed logon attempts within 60 seconds

&nbsp; </description>

&nbsp; <mitre>

&nbsp;   <id>T1110</id>

&nbsp; </mitre>

&nbsp; <group>authentication,windows,bruteforce,</group>

</rule>



\## Validation Procedure

\### Validate Rule Syntax

sudo /var/ossec/bin/wazuh-analysisd -t

\### Restart Wazuh Manager

sudo systemctl restart wazuh-manager



\## Attack Simulation

runas /user:socuser cmd



Enter incorrect password five times within 60 seconds.



\## Detection Results

Observed behavior:



* First 5 failed logon attempts generated normal authentication\_failed alerts (Rule ID 60122).
* On the 5th failed attempt, custom rule ID 110501 triggered.
* Only one brute force alert was generated.



This confirms:

* Correlation logic functioning correctly
* Threshold-based detection working
* Alert noise reduced
* Behaviour-based detection successfully implemented



\## MITRE ATT\&CK Mapping

Technique:

* T1110 — Brute Force

Tactics:

* Initial Access
* Credential Access





