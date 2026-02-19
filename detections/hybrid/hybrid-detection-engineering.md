\# Hybrid Detection Engineering — Behaviour-Driven Correlation (Day 3)



\## Objective



Transition from basic hybrid telemetry into behaviour-driven hybrid detection engineering by correlating endpoint behaviour with network activity.



Focus areas:



\- Improve hybrid detection beyond simple chaining

\- Reduce alert noise through rule tuning

\- Implement behaviour-based correlation logic

\- Apply SOC investigation workflow mindset

\- Demonstrate detection engineering practices



---



\## Lab Environment



\### SIEM Platform

\- Wazuh Manager / Indexer / Dashboard

\- Ubuntu Server



\### Endpoint Telemetry

\- Windows 11 endpoint

\- Sysmon installed

\- Custom behaviour detection rules



\### Network Telemetry

\- Suricata IDS

\- Filtered eve-wazuh.json pipeline

\- DNS + TLS telemetry ingestion



---



\## Hybrid Detection Design



\### Behaviour Gate (Endpoint)



Rule ID: \*\*200705\*\*



Detects suspicious certutil download behaviour:



\- certutil execution

\- URL download parameters

\- aligned with MITRE ATT\&CK T1105 (Ingress Tool Transfer)



This rule acts as the trigger condition for hybrid correlation.



---



\### Network Telemetry Rules



Visibility rules built from Suricata telemetry:



\- \*\*300001\*\* — DNS telemetry visibility

\- \*\*300002\*\* — TLS telemetry visibility



Data source:

/var/log/suricata/wazuh/eve-wazuh.json







Fields parsed via JSON decoder:



\- event\_type

\- src\_ip

\- dest\_ip

\- dns.rrname

\- tls.sni



---



\## Hybrid Correlation Logic



Goal:



Suspicious Endpoint Behaviour

\+

Observed Network Activity

=

High Confidence Hybrid Detection




\### Hybrid Escalation Rules



\#### DNS Hybrid Detection



Rule ID: \*\*400001\*\*



Conditions:



\- DNS event observed

\- Previous certutil behaviour detected



Purpose:



Correlate endpoint execution with outbound DNS activity.



---



\#### TLS Hybrid Detection



Rule ID: \*\*400002\*\*



Conditions:



\- TLS connection observed

\- Previous certutil behaviour detected



Purpose:



Detect encrypted outbound communication following suspicious execution.



---



\## Noise Reduction Strategy



Initial hybrid rules produced high alert volume due to:



\- Normal Windows background DNS traffic

\- Multiple DNS/TLS events per single action



Acknowledged engineering challenge:



Hybrid detection must balance visibility and signal quality.



\### Implemented Improvements



1\. Behaviour gate using certutil detection

2\. Rule tuning using:



frequency="2"

timeframe="60"



This reduces duplicate alerts by requiring multiple matching events within a time window.



---



\## Detection Workflow (SOC Engineering Mindset)



Instead of correlating all network traffic:



1\. Detect high-confidence endpoint behaviour.

2\. Observe network telemetry context.

3\. Escalate only when both signals appear.



This reduces noise and aligns with real SOC workflows.



---



\## Validation Steps



1\. Execute controlled test:



certutil.exe -urlcache -f https://example.com testfile.txt




2\. Confirm rule firing:



\- 200705 (endpoint behaviour)

\- 300001 / 300002 (network telemetry)

\- 400001 / 400002 (hybrid escalation)



3\. Verify alerts in:

/var/ossec/logs/alerts/alerts.json




---



\## Key Learning Outcomes



\- Hybrid detection requires behaviour gating.

\- Network telemetry alone produces excessive noise.

\- Wazuh rule correlation depends on correct field mapping.

\- logtest is critical for understanding decoded fields.

\- Detection engineering involves iterative tuning, not single rule creation.



---



\## Architecture Summary

Sysmon Endpoint Behaviour

↓

Wazuh Detection Rule (200705)

↓

Suricata DNS/TLS Telemetry

↓

Hybrid Correlation Rules (400001 / 400002)

↓

High Confidence Detection Alert





---



\## MITRE ATT\&CK Mapping



\- T1105 — Ingress Tool Transfer

\- Command and Control (C2)



---



\## Result



Successfully implemented behaviour-driven hybrid detection combining endpoint and network telemetry with noise reduction tuning.



This demonstrates transition from SOC analyst alert consumption to detection engineering design.




