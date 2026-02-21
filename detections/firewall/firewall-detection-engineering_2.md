\# Phase 3 — Firewall Detection Engineering (Perimeter Telemetry Integration)

\## Day 2 — Firewall Detection Engineering \& Hybrid Correlation



\*\*Date:\*\* 2026-02-21  

\*\*Stack:\*\* Wazuh SIEM + Ubuntu UFW firewall telemetry + Suricata IDS + Windows 11 Sysmon endpoint



---



\## Objective

\- Build perimeter-focused detection logic (behaviour-based)

\- Detect repeated blocked connection attempts (scan-like behaviour)

\- Detect suspicious blocked attempts to high destination ports

\- Introduce hybrid correlation thinking (IDS + firewall)



---



\## Evidence: Firewall telemetry present in Wazuh

\*\*Source:\*\* `/var/log/ufw.log` → Wazuh archives/alerts



Example event (UFW BLOCK observed in alerts):

\- `\[UFW BLOCK] ... SRC=192.168.72.129 ... DPT=55555`



---



\## Rules Implemented (Wazuh local\_rules.xml)



> Group wrapper used:

`<group name="local,firewall">`



\### 400100 — Firewall visibility: UFW BLOCK

\- Detects any UFW BLOCK event



\### 400101 — Port-specific: UFW BLOCK to 1514/1515

\- Detects blocked attempts to Wazuh-related ports



\### 400110 — Behaviour: Repeated blocked attempts (scan-like)

\- Triggers when multiple 400101 events occur within 60 seconds  

\- Tuned to match lab baseline traffic timing



\### 400120 — Suspicious blocked attempt to high destination port

\- Detects `\[UFW BLOCK]` attempts to high ports (e.g., 55555)



\### 400130 — Hybrid correlation (IDS + firewall)

\- Triggers when Suricata DNS telemetry (300001) is followed by firewall repeated blocks (400110)



---



\## Testing / Triggering



\### Trigger firewall BLOCK from Windows

```powershell

Test-NetConnection 192.168.72.130 -Port 1514

Test-NetConnection 192.168.72.130 -Port 55555

 ## Reliable burst generator:

1..20 | % {

&nbsp; $c = New-Object System.Net.Sockets.TcpClient

&nbsp; try { $c.Connect("192.168.72.130",1514) } catch {}

&nbsp; $c.Close()

&nbsp; Start-Sleep -Milliseconds 200

}



\## Trigger Suricata DNS telemetry (for correlation)

nslookup example.com



\## Validation Commands (Wazuh)



Confirm rules fired:

sudo jq 'select(.rule.id=="400100") | {time:.timestamp,id:.rule.id,desc:.rule.description}' /var/ossec/logs/alerts/alerts.json | tail -n 5

sudo jq 'select(.rule.id=="400101") | {time:.timestamp,id:.rule.id,desc:.rule.description}' /var/ossec/logs/alerts/alerts.json | tail -n 5

sudo jq 'select(.rule.id=="400110") | {time:.timestamp,id:.rule.id,desc:.rule.description}' /var/ossec/logs/alerts/alerts.json | tail -n 5

sudo jq 'select(.rule.id=="400120") | {time:.timestamp,id:.rule.id,desc:.rule.description,log:.full\_log}' /var/ossec/logs/alerts/alerts.json | tail -n 3

sudo jq 'select(.rule.id=="400130") | {time:.timestamp,id:.rule.id,desc:.rule.description}' /var/ossec/logs/alerts/alerts.json | tail -n 5

