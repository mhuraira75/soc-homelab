\# Day 2 — Hybrid Detection Engineering (Endpoint + Network Telemetry)



\## Goal

Integrate Suricata DNS/TLS telemetry into the Wazuh SOC workflow and build the first practical hybrid behavior scenario:

\*\*endpoint process → DNS → TLS\*\*.



\## Environment

\- Wazuh SIEM (Manager / Indexer / Dashboard) on Ubuntu Server

\- Windows 11 endpoint with Sysmon telemetry

\- Suricata IDS capturing network telemetry (eve.json)

\- Filtered Suricata feed for Wazuh ingestion



\## Key Problem Encountered

Direct ingestion of `/var/log/suricata/eve.json` into Wazuh caused:

\- `wazuh-analysisd: ERROR: Too many fields for JSON decoder.`



\## Fix (Engineering Approach)

Created a reduced Suricata feed that preserves investigation-relevant fields only:

\- DNS: rrname, rrtype, rcode

\- TLS: sni, version, subject, issuerdn

Output file:

\- `/var/log/suricata/wazuh/eve-wazuh.json`



Wazuh then ingests the reduced feed successfully.



\## Wazuh Ingestion (ossec.conf)

Added localfile:



```xml

<localfile>

&nbsp; <log\_format>json</log\_format>

&nbsp; <location>/var/log/suricata/wazuh/eve-wazuh.json</location>

</localfile>



\## Suricata → Wazuh Filter Script



A tail + jq pipeline outputs only DNS/TLS minimal JSON lines:

* Script: scripts/suricata\_eve\_to\_wazuh.sh
* Input: /var/log/suricata/eve.json
* Output: /var/log/suricata/wazuh/eve-wazuh.json



\## Network Visibility Alerts (Wazuh Rules)



Created two visibility rules to promote Suricata events into alerts:

* 300001 — Suricata DNS event observed
* 300002 — Suricata TLS event observed



\## First Practical Hybrid Scenario (Evidence Chain)



Controlled test on Windows:

powershell.exe -NoProfile -WindowStyle Hidden -Command "iwr https://example.com -UseBasicParsing | Out-Null"





Observed hybrid timeline (example):

* Sysmon Process Create (PowerShell hidden + iwr)
* DNS query for example.com (Suricata)
* TLS session with SNI=example.com (Suricata)



\## Hybrid Detection (Behavior Chain)

High-confidence hybrid alert fired:

* 300011 — Hybrid Detection (High Confidence): Endpoint execution followed by outbound TLS activity



\## Outcome

* Suricata DNS/TLS telemetry integrated into Wazuh SOC workflow
* Hybrid investigation timeline validated (endpoint + network)
* First hybrid detection alert operational
