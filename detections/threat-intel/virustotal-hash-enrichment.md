VirusTotal Threat Intelligence Enrichment

Hash-Based Investigation – SOC Home Lab

Overview



Today I integrated VirusTotal API v3 threat intelligence enrichment into my SOC home lab workflow.



The objective was to:



Extract real SHA256 hashes from Sysmon Process Create logs (Event ID 1)



Perform bulk enrichment using the VirusTotal API



Interpret AV engine verdicts correctly



Apply SOC-grade reasoning beyond simple hash reputation



This simulates how real SOC environments enrich file artifacts during investigations.



Lab Environment



SIEM: Wazuh



Endpoint Telemetry: Sysmon (Windows)



Log Source: /var/ossec/logs/archives/archives.json



Threat Intelligence Source: VirusTotal API v3



Automation: Bash + curl + jq



Step 1 — Extract SHA256 Hashes from Sysmon Logs



Hashes were extracted from Sysmon Event ID 1 (Process Create):



sudo jq -r '

select(.data.win.system.eventID=="1")

| (.data.win.eventdata.hashes? // empty)

| capture("SHA256=(?<sha256>\[A-Fa-f0-9]{64})").sha256

' /var/ossec/logs/archives/archives.json | sort -u



This produced real execution hashes from the monitored Windows endpoint.



Step 2 — Secure API Key Configuration



The VirusTotal API key was configured securely using an environment variable:



export VT\_API\_KEY="YOUR\_API\_KEY"



The key was not hardcoded inside scripts, following secure operational practice.



Step 3 — Bulk Hash Enrichment Script



A SOC-style enrichment script was created:



\#!/bin/bash

API\_KEY="${VT\_API\_KEY}"

INPUT\_FILE="hashes.txt"

SLEEP\_SECONDS=16



if \[ -z "$API\_KEY" ]; then

&nbsp; echo "ERROR: VT\_API\_KEY not set."

&nbsp; exit 1

fi



while read -r HASH; do

&nbsp; HASH="$(echo "$HASH" | tr -d '\[:space:]')"

&nbsp; \[ -z "$HASH" ] \&\& continue



&nbsp; echo "Checking $HASH ..."



&nbsp; RESPONSE="$(curl -s -H "x-apikey: $API\_KEY" \\

&nbsp; "https://www.virustotal.com/api/v3/files/$HASH")"



&nbsp; ERR\_CODE="$(echo "$RESPONSE" | jq -r '.error.code // empty')"

&nbsp; if \[ -n "$ERR\_CODE" ]; then

&nbsp;   echo "$RESPONSE" | jq '{error: .error}'

&nbsp;   sleep $SLEEP\_SECONDS

&nbsp;   continue

&nbsp; fi



&nbsp; echo "$RESPONSE" | jq -r '

&nbsp;   .data.attributes.last\_analysis\_stats

&nbsp;   | "Malicious: \\(.malicious) | Suspicious: \\(.suspicious) | Undetected: \\(.undetected) | Harmless: \\(.harmless)"

&nbsp; '



&nbsp; echo "---------------------------------------------"

&nbsp; sleep $SLEEP\_SECONDS



done < "$INPUT\_FILE"



The script includes:



Rate-limit handling (free tier safe)



Error detection



Clean output formatting



Secure API usage



Step 4 — Enrichment Results



Example output:



Malicious: 0 | Suspicious: 0 | Undetected: 72 | Harmless: 0

Malicious: 0 | Suspicious: 0 | Undetected: 68 | Harmless: 0

Malicious: 0 | Suspicious: 0 | Undetected: 72 | Harmless: 0

SOC Interpretation

Key Observations



No engines flagged the hashes as malicious.



High "Undetected" counts (~70 engines).



No positive threat classifications.



Hashes originated from a controlled Windows lab endpoint.



Important SOC Insight



"0 malicious detections" does not automatically mean safe.



VirusTotal reputation must always be combined with:



Parent-child process analysis



Execution path review



Command-line inspection



Network correlation



Persistence analysis



Threat intelligence is enrichment — not a verdict engine.



Real SOC Workflow Simulated



Alert triggers in SIEM



Extract file hash



Enrich via VirusTotal API



Classify using threat intelligence



Pivot to behavioral investigation



Skills Demonstrated



Threat Intelligence Enrichment



VirusTotal API Integration



Secure API Handling



Bash Automation



JSON Parsing with jq



SOC Investigation Methodology



Detection Engineering Workflow



Conclusion



All tested hashes returned:



0 malicious detections



High undetected counts



No suspicious indicators



Based on threat intelligence alone, no malware was identified.



However, proper SOC methodology requires behavioral validation and contextual investigation.



This exercise successfully integrated automated threat intelligence enrichment into the SOC home lab and strengthened detection engineering capabilities.

