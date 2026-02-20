\# Day 6 — High-Confidence Escalation \& Detection Hardening (Endpoint + Network)



\## Goal

Move from hybrid investigation workflow to SOC-grade escalation logic:

\- \*\*Low confidence\*\*: noise / allowlisted traffic (downgraded)

\- \*\*Medium confidence\*\*: hybrid correlation (review)

\- \*\*High confidence\*\*: endpoint behaviour + external TLS + non-allowlisted SNI (escalate)



\## Environment

\- Wazuh SIEM (Manager/Indexer/Dashboard) on Ubuntu Server

\- Windows 11 endpoint with Sysmon telemetry

\- Suricata IDS integrated into Wazuh via filtered feed:

&nbsp; - `/var/log/suricata/wazuh/eve-wazuh.json`

\- DNS + TLS telemetry confirmed

\- Hybrid correlation already working (Days 3–5)



\## Starting Detection State

\- Endpoint anchor:

&nbsp; - `200705` — Certutil suspicious download activity

&nbsp; - `200715` — High confidence: Explorer → certutil download (parent-child)

&nbsp; - (optional broader) `200714` — LOLBins from PowerShell/CMD

\- Hybrid correlations:

&nbsp; - `400001` — Hybrid DNS correlation (tuned)

&nbsp; - `400002` — Hybrid TLS correlation (tuned)

\- Existing tuning:

&nbsp; - WPAD filtered

&nbsp; - Reverse DNS reduced

&nbsp; - TLS without SNI filtered

&nbsp; - Microsoft telemetry partially allowlisted

&nbsp; - Downgrade rules active for PTR + Microsoft noise



---



\## Day 6 Objective

\### Build SOC prioritization tiers

1\) \*\*Low confidence (Downgrade / noise)\*\*

&nbsp;  - Microsoft/CDN/telemetry TLS SNI patterns should not create SOC-level noise.



2\) \*\*Medium confidence (Eligible / investigation)\*\*

&nbsp;  - External TLS to non-allowlisted SNI should be reviewable (not a page).



3\) \*\*High confidence (Escalation)\*\*

&nbsp;  - Strong endpoint anchor + external TLS + non-allowlisted SNI within \*\*X seconds\*\* should generate an escalation alert.



---



\## Implementation



\### A) Low Confidence — TLS Allowlist (Downgrade Layer)

Problem: Hybrid TLS correlation (`400002`) was firing on normal Microsoft traffic.



Fix: Create allowlist rules chained off `400002`, lowering severity for known benign Microsoft/CDN/telemetry domains.



\*\*Rules\*\*

\- `401000` (lvl 3): Microsoft + CDN + auth endpoints downgraded

\- `401001` (lvl 3): Microsoft telemetry endpoints downgraded



\*\*Validation\*\*

Observed allowlist hits (lvl 3) for:

\- `login.live.com`

\- `logincdn.msftauth.net`

\- `assets.msn.com`

\- `edge-consumer-static.azureedge.net`

\- `browser.events.data.msn.com`



This prevented Microsoft background traffic from escalating.



---



\### B) Medium Confidence — External TLS Eligible (Non-Allowlisted)

Create a gating rule that marks “eligible for escalation” events:

\- Must be a TLS correlation event (`400002`)

\- Must be \*\*external destination\*\*

\- Must not be internal resolver traffic (`dest\_ip != 192.168.72.2`)

\- Must not be RFC1918 destination ranges

\- Must not match the allowlist patterns (defense-in-depth)



\*\*Rule\*\*

\- `402000` (lvl 11): External TLS to non-allowlisted SNI (eligible)



\*\*Validation\*\*

Confirmed:

\- `402000` fired on external non-allowlisted SNI:

&nbsp; - `example.org` → `dst=104.18.3.24`

\- No evidence of internal resolver destinations in `402000`.



---



\### C) High Confidence — SOC Escalation

Escalation condition:

\- Endpoint anchor (`200715` primary; optional `200705/200714`)  

\- + External TLS eligible (`402000`)

\- + Within timeframe (X seconds)



\*\*Time window\*\*

\- `timeframe = 120` seconds (X = 120s)



\*\*Rules\*\*

\- `402010` (lvl 16): Escalate on `200715` + `402000` within 120s  

\- (Optional) additional tiers:

&nbsp; - `402011` (lvl 15): `200705` + `402000`

&nbsp; - `402012` (lvl 14): `200714` + `402000`



\*\*Validation (Controlled Test)\*\*

A controlled run produced:

\- `402000 lvl=11 sni=example.org dst=104.18.3.24`

\- `402010 lvl=16 sni=example.org dst=104.18.3.24`



---



\## Final SOC Prioritization Model

\- \*\*Low (Noise / Downgrade):\*\*

&nbsp; - `401000`, `401001` → lvl 3 (Microsoft/CDN/telemetry)

\- \*\*Medium (Investigation / Eligible):\*\*

&nbsp; - `402000` → lvl 11 (external TLS + non-allowlisted SNI)

\- \*\*High (SOC Escalation):\*\*

&nbsp; - `402010` → lvl 16 (endpoint anchor + eligible TLS within 120s)



---



\## Reliability Checks (Non-Firing Requirements)

Escalation layer must NOT fire on:

\- Microsoft telemetry

\- internal resolver traffic

\- WPAD

\- reverse DNS PTR



Results:

\- Microsoft traffic correctly downgraded via allowlist rules.

\- `402000` only showed external destinations; internal resolver traffic excluded.

\- Escalation only triggered during controlled endpoint+network test.



---



\## Notes / Future Hardening

\- Expand allowlist patterns to include additional known benign domains (lab-specific).

\- Add same-host correlation constraints (agent IP ↔ TLS src\_ip) if multi-endpoint scaling is needed.

\- Add escalation suppression for “test domains” (example.org/example.com) for cleaner demos.

