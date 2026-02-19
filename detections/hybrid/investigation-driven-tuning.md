\# Day 4 — SOC Hybrid Detection Engineering (Endpoint + Network)

\## Investigation-Driven Refinement (From “it fires” to “it’s useful”)



\### Objective

Improve hybrid detections so alerts contain investigation-ready context and avoid obvious background noise, moving from simple triggering to SOC-usable signal.



\### Environment

\- Wazuh SIEM (Manager/Indexer/Dashboard) on Ubuntu Server

\- Windows 11 endpoint with Sysmon telemetry

\- Suricata IDS integrated into Wazuh via filtered `eve-wazuh.json`

\- DNS + TLS telemetry confirmed

\- Hybrid correlation logic already working (endpoint behaviour → DNS/TLS)



---



\## 1) Baseline: What the SOC analyst actually sees

Initial hybrid alerts fired successfully, but investigation context revealed large amounts of normal background activity after the endpoint behaviour.



\### Example anchor (Endpoint)

\- Rule: \*\*200705\*\*

\- Behaviour: `certutil.exe -urlcache -f https://example.com testfile.txt`

\- Host/User: `WIN-ENDPOINT-01` / `socuser`

\- Parent: `powershell.exe`



\### Example network enrichment (Noise discovered during triage)

\- DNS: `wpad.localdomain` (frequent)

\- TLS: `edge.microsoft.com`, telemetry domains, plus many TLS events with missing SNI (`n/a`)

\- Reverse DNS lookups: `\*.in-addr.arpa`



This is typical SOC reality: if the alert is not tuned, analysts waste time on background DNS/TLS that does not confirm maliciousness.



---



\## 2) Investigation-driven triage workflow (Hybrid Alerts)

When hybrid rules fire, triage follows this order:



\### Step A — Validate the anchor behaviour (Endpoint)

Confirm the endpoint behaviour is truly suspicious:

\- Host + user (who did it, where)

\- Process + parent chain (how it launched)

\- Command line (external URL? user-writable destinations? obfuscation?)

\- Does this behaviour align with known attacker tradecraft (LOLBins like certutil)?



\### Step B — Pull network context (DNS/TLS)

Use Suricata fields to enrich the case:

\- DNS: `dns.rrname`, `src\_ip`, `dest\_ip` (DNS server), `rcode`

\- TLS: `tls.sni`, `dest\_ip` (remote IP), TLS version



\### Step C — Decide if network context strengthens suspicion

\- Likely benign: WPAD, reverse DNS, common Microsoft/telemetry endpoints, browser background lookups

\- More suspicious: unknown domains, odd TLDs, IP-only traffic, repeated beacons, domain mismatch with expected user activity



\### Step D — Escalation criteria (SOC value)

Escalate when:

\- Strong endpoint anchor behaviour is present \*\*AND\*\*

\- Network enrichment shows a suspicious domain/SNI or destination IP not explained by normal background activity.



---



\## 3) Detection tuning actions (Day 4)

\### Goal

Reduce obvious noise while preserving hybrid detection capability.



\### What changed (rules 400001 / 400002)

\- \*\*Added quality gates\*\*

&nbsp; - DNS requires a real rrname

&nbsp; - TLS requires SNI present (reduces low-value `n/a` spam)

\- \*\*Added safe allowlists\*\*

&nbsp; - DNS: excluded `wpad.localdomain`

&nbsp; - TLS: excluded obvious Microsoft telemetry domains

\- \*\*Planned/optional noise suppression\*\*

&nbsp; - Exclude reverse DNS lookups: `\*.in-addr.arpa` (background enrichment)



\### Updated rules (local\_rules.xml)

Rule IDs:

\- \*\*400001\*\* — DNS after suspicious certutil behaviour (tuned)

\- \*\*400002\*\* — TLS after suspicious certutil behaviour (tuned)



Key enrichment fields available in alerts:

\- DNS: `.data.dns.rrname`, `.data.src\_ip`, `.data.dest\_ip`, `.data.dns.rcode`

\- TLS: `.data.tls.sni`, `.data.src\_ip`, `.data.dest\_ip`, `.data.tls.version`



---



\## 4) Verification

\### Trigger method (controlled)

On Windows endpoint:

\- `certutil -urlcache -f https://example.com testfile\*.txt`



\### Expected outcome

\- Hybrid detections still fire for the test signal:

&nbsp; - DNS: `rrname=example.com`

&nbsp; - TLS: `sni=example.com`

\- Reduced background noise:

&nbsp; - WPAD filtered

&nbsp; - TLS without SNI filtered

&nbsp; - (Optional) reverse DNS filtered



\### Sample verification output (fields shown)

\- `rule.id`, `rrname/sni`, `src\_ip`, `dest\_ip`

\- This ensures alerts are investigation-ready without needing to manually pivot across raw logs.



---



\## 5) SOC notes (what I’d do next in a real environment)

\- Expand allowlists carefully using evidence (top talkers / frequent rrnames)

\- Add “suspicious domain heuristics” (rare TLDs, newly seen domains, high entropy subdomains)

\- Add process-aware network correlation (e.g., tie `certutil.exe` to immediate DNS/TLS destinations where possible)

\- Build a small “known good” baseline list for the environment (Edge/Windows update/telemetry)



---



\### Outcome (Day 4)

Hybrid detection moved from \*\*“it fires”\*\* to \*\*“it’s useful in a SOC case”\*\*:

\- Evidence-driven tuning

\- Investigation-first workflow

\- Cleaner, portfolio-quality hybrid detection output



