\# Day 5 — Correlation Maturity \& Analyst Workflow (Endpoint + Network)



\## Objective (Day 5)

Move from “hybrid enrichment” to a SOC-realistic investigation workflow.



Target workflow:

\*\*Endpoint behaviour → DNS → TLS → destination IP context\*\*  

with confidence layering for triage (reduce Microsoft/PTR noise, preserve high-signal chains).



---



\## Environment

\- Wazuh SIEM (Manager/Indexer/Dashboard) on Ubuntu Server

\- Windows 11 endpoint (Sysmon telemetry)

\- Suricata IDS integrated into Wazuh via filtered feed:

&nbsp; - Source: `/var/log/suricata/eve.json`

&nbsp; - Filtered feed: `/var/log/suricata/wazuh/eve-wazuh.json`

\- DNS + TLS telemetry confirmed

\- Behaviour-driven hybrid correlation working

\- Investigation-driven tuning completed (Day 4)



---



\## Current Detection State

\- Endpoint anchor detection: \*\*high-confidence certutil behaviour\*\*

\- Hybrid DNS correlation: \*\*Rule 400001 (tuned)\*\*

\- Hybrid TLS correlation: \*\*Rule 400002 (tuned)\*\*

\- Noise reduction already applied:

&nbsp; - WPAD filtered

&nbsp; - Reverse DNS reduced

&nbsp; - TLS without SNI filtered

&nbsp; - Microsoft telemetry partially allowlisted



---



\## Why Day 5 Matters (SOC workflow maturity)

Hybrid detection is only “SOC-ready” if an analyst can triage quickly from the alert:



\*\*What happened?\*\* (endpoint behaviour)  

\*\*What domain?\*\* (DNS rrname / TLS SNI)  

\*\*Where did it go?\*\* (dest IP)  

\*\*Is it internal resolver noise or external comms?\*\*  

\*\*Is it Microsoft/known-good telemetry?\*\*



Since endpoint + network events arrive as separate records, Day 5 focuses on:

1\) building a repeatable analyst pivot workflow, and

2\) applying confidence layering (downgrade low-signal patterns, keep high-signal chains).



---



\## Telemetry Validation (Proof of End-to-End Chain)



\### Endpoint Anchor (Sysmon Process Create)

Observed certutil execution on endpoint:



\- Image: `C:\\\\Windows\\\\System32\\\\certutil.exe`

\- CommandLine:

&nbsp; `"C:\\\\WINDOWS\\\\system32\\\\certutil.exe" -urlcache -split -f https://example.com testfile.txt`

\- Parent: `C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe`

\- User: `DESKTOP-ON8B91Q\\\\socuser`



\### Network Pivot (TLS after endpoint behaviour)

Hybrid TLS alerts show external destination and SNI:



\- SNI: `example.com`

\- src\_ip: `192.168.72.129`

\- dest\_ip: `104.18.27.120`

\- Examples:

&nbsp; - `2026-02-20T13:04:22Z sni=example.com dest=104.18.27.120 src=192.168.72.129`

&nbsp; - `2026-02-20T13:17:06Z sni=example.com dest=104.18.27.120 src=192.168.72.129`



\### DNS Pivot (Resolver context)

Hybrid DNS alert for same activity:

\- rrname: `example.com`

\- rrtype: `A`

\- dest\_ip (resolver): `192.168.72.2`

\- rcode: `NOERROR`



---



\## Analyst Triage Workflow (Copy/Paste Pivots)



\### Step 1 — Confirm endpoint behaviour (certutil execution)

```bash

sudo jq '

select(.agent.name=="WIN-ENDPOINT-01")

| select(.data.win.system.channel=="Microsoft-Windows-Sysmon/Operational")

| select(.data.win.system.eventID=="1")

| select((.data.win.eventdata.image? // "")|test("(?i)\\\\\\\\certutil\\\\.exe$"))

| {

time:.timestamp,

image:.data.win.eventdata.image,

cmd:.data.win.eventdata.commandLine,

parent:.data.win.eventdata.parentImage,

user:(.data.win.eventdata.user // "n/a")

}

' /var/ossec/logs/archives/archives.json | tail -n 10


## Analyst Notes

* Validate suspicious parent-child chain (e.g., PowerShell spawning certutil).
* Confirm command-line intent (download/transfer indicators).



\### Step 2 — DNS pivot (domain + resolver context)

sudo jq '

select(.rule.id=="400001")

| {

time:.timestamp,

rrname:(.data.dns.rrname // "n/a"),

rrtype:(.data.dns.rrtype // "n/a"),

rcode:(.data.dns.rcode // "n/a"),

src:(.data.src\_ip // "n/a"),

resolver:(.data.dest\_ip // "n/a")

}

' /var/ossec/logs/alerts/alerts.json | tail -n 20


## Analyst Notes

* dest\_ip is often internal DNS resolver (expected).
* rrtype=PTR and .in-addr.arpa indicates reverse DNS noise (downgrade).





\### Step 3 — TLS pivot (SNI + external destination IP)

sudo jq -r '

select(.rule.id=="400002")

| "\\(.timestamp) sni=\\(.data.tls.sni // "n/a") dest=\\(.data.dest\_ip // "n/a") src=\\(.data.src\_ip // "n/a")"

' /var/ossec/logs/alerts/alerts.json | tail -n 20



\## Analyst Notes

* Treat dest\_ip as the primary external pivot for reputation/context checks.
* If SNI is missing/null, treat as lower confidence (already filtered where possible).





\## Confidence Layering (SOC Decision Logic)

\### HIGH confidence (page / investigate fast)

* Strong endpoint behaviour (certutil with transfer intent) AND
* TLS to external dest\_ip AND
* SNI/domain is not allowlisted (not common Microsoft/Office telemetry)



\### MEDIUM confidence (investigate, but de-prioritize if benign context)

* Endpoint behaviour present AND
* DNS/TLS present BUT domain/SNI suggests common benign infra



\### LOW confidence (noise)

* Reverse DNS PTR (.in-addr.arpa) activity
* WPAD lookups
* Microsoft/Office telemetry SNI patterns





\## Detection Notes / Improvements Logged 

* Verified that the filtered Suricata feed contains SOC-relevant pivots:

1. DNS: rrname/rrtype/rcode
2. TLS: sni/version + (when available) subject/issuerdn
3. src/dest IPs



* Implemented investigation workflow pivots to make alerts actionable even when endpoint+network records are separate.



* Next improvement (optional): extend filter feed to include DNS resolved IP (A record) for faster domain→IP pivoting.
