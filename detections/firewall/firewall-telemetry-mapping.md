\# Firewall Telemetry Mapping — UFW → Wazuh SIEM

\## Phase 3 — Firewall Detection Engineering (Perimeter Telemetry Integration)

\### Day 1 — Telemetry Foundation, Field Mapping \& Baseline Establishment



---



\## 1. Objective



Integrate Ubuntu UFW firewall logs into Wazuh SIEM, validate ingestion, analyze raw log structure, map critical detection fields, and establish a baseline understanding of normal firewall behaviour.



This phase expands SOC visibility beyond:



\- Endpoint telemetry (Sysmon)

\- Network telemetry (Suricata IDS)

\- Hybrid detection and escalation logic



Firewall telemetry introduces perimeter-layer visibility to the detection stack.



---



\## 2. Environment



\- SIEM: Wazuh (Manager + Indexer + Dashboard)

\- Firewall: Ubuntu UFW

\- Endpoint: Windows 11 with Sysmon

\- Network IDS: Suricata (already integrated)



Firewall Log Source:

/var/log/ufw.log

---



\## 3. Telemetry Pipeline Architecture



Firewall telemetry flow validated end-to-end:

UFW Firewall

↓

Linux Kernel (UFW ALLOW / BLOCK events)

↓

rsyslog

↓

/var/log/ufw.log

↓

Wazuh Logcollector

↓

archives.json (raw event storage)

↓

Wazuh Analysis Engine



Validation steps performed:



\- UFW enabled and logging activated

\- Kernel-level events confirmed using:



dmesg | grep UFW



\- rsyslog routing configured to generate `/var/log/ufw.log`

\- Wazuh ingestion verified via:





/var/ossec/logs/archives/archives.json







Telemetry ingestion successfully confirmed.



---



\## 4. Sample Raw Firewall Event



2026-02-20T20:00:30.627325+00:00 wazuh-siem kernel: \[UFW BLOCK] IN=ens33 OUT= MAC=00:0c:29:e2:9b:ef SRC=192.168.72.129 DST=192.168.72.130 LEN=52 TOS=0x00 PREC=0x00 TTL=128 ID=29679 DF PROTO=TCP SPT=59643 DPT=1514 WINDOW=65535 RES=0x00 SYN URGP=0







Observations:



\- Logs originate from kernel

\- Structured tokens embedded in plain text

\- Action decision visible early in message

\- No structured field extraction by default decoder

\- Requires parsing logic for structured analytics



---



\## 5. Field Mapping (Structured Token Analysis)



UFW logs use key-value token format inside a syslog message.



| Detection Field | Log Token | Example | Description |

|-----------------|-----------|---------|-------------|

| action | `\[UFW BLOCK]` | BLOCK | Firewall decision |

| src\_ip | `SRC=` | 192.168.72.129 | Originating host |

| dest\_ip | `DST=` | 192.168.72.130 | Target host |

| src\_port | `SPT=` | 59643 | Source port |

