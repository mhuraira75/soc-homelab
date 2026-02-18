\# Hybrid Detection Engineering — Day 1

\## Introducing Network Telemetry (Suricata IDS Integration)



---



\## Objective



Transition the SOC home lab from endpoint-only monitoring into hybrid detection engineering by integrating network telemetry alongside existing Sysmon endpoint visibility.



The goal of this phase is to build behaviour-based detection capabilities using both endpoint and network data sources.



---



\## Environment



\### SIEM Platform

\- Wazuh Manager / Indexer / Dashboard

\- Ubuntu Server



\### Endpoint

\- Windows 11

\- Wazuh Agent installed

\- Sysmon telemetry enabled



\### Network Sensor

\- Suricata IDS (AF\_PACKET mode)

\- Interface: ens33



---



\## Threat Detection Philosophy



Hybrid detection engineering focuses on correlating:



\- Endpoint behaviour (process execution)

\- Network behaviour (DNS / TLS / flows)



Instead of relying on single-source alerts.



---



\## Deployment Steps



\### 1. Install Suricata



```bash

sudo apt update

sudo apt install suricata -y



\### 2. Configure Capture Interface 



```bash

/etc/suricata/suricata.yaml



Set: 

af-packet:

&nbsp; - interface: ens33





\### 3. Enable JSON Telemetry (eve.json)

Ensure:

eve-log:

&nbsp; enabled: yes





\### 4. Start Suricata



```bash

sudo systemctl enable suricata

sudo systemctl restart suricata





\## Telemetry Verification

Network visibility validated using controlled traffic.



\### DNS Validation

Command executed on Windows endpoint:

nslookup example.com

Suricata captured:

* DNS query
* DNS response
* Source host identification

Example extraction:

sudo jq -c 'select(.event\_type=="dns")' /var/log/suricata/eve.json



\### TLS Validation

Browser navigation:

https://example.com

Captured:

* TLS handshake
* SNI hostname
* Destination IP
* TLS version

Example:

SNI: example.com

TLS Version: TLS 1.3



\## Hybrid Investigation Workflow



Correlated across telemetry layers:



\### Endpoint Evidence

* Process: msedge.exe
* Sysmon EventID 1 (Process Create)



\### Network Evidence

* DNS query → example.com
* TLS session → example.com





\## Key Learning Outcomes

* Network sensors provide passive visibility without endpoint installation.
* TLS encryption hides payload but SNI reveals destination hostname.
* Hybrid correlation allows behaviour-based investigation.
