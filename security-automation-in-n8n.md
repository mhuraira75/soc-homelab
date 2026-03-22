\# 🚀 Automated SSH Brute-Force Detection \& IP Enrichment  

\### Splunk + n8n + VirusTotal | SOC Automation Project



\---



\## 📌 Project Overview



This project demonstrates a \*\*real-world SOC automation workflow (SOAR-style)\*\* built using:



\- Splunk → Detection \& Alerting  

\- n8n → Workflow Automation  

\- VirusTotal API → Threat Intelligence Enrichment  



The workflow simulates a \*\*brute-force SSH attack\*\*, detects it in Splunk, sends the alert to n8n via webhook, enriches the attacker IP, and automatically classifies the threat.



\---



\## 🎯 Objective



To build an automated pipeline that:



1\. Detects repeated failed SSH login attempts  

2\. Sends alerts from Splunk to n8n  

3\. Enriches attacker IP using VirusTotal  

4\. Applies decision logic (malicious vs clean)  

5\. Outputs structured SOC-ready results  



\---



\## 🧱 Architecture



Attacker → Ubuntu (auth.log) → Splunk (Detection \& Alert) → Webhook → n8n → VirusTotal API → Decision Logic → SOC Output



\---



\## ⚙️ Lab Setup



\### 🖥️ Systems



\- Ubuntu Server (Wazuh-SIEM VM)  

&#x20; - Log source: /var/log/auth.log  



\- Windows 11 Host  

&#x20; - Docker installed  

&#x20; - n8n running via Docker  



\---



\## 🔥 Step 1 — Attack Simulation



Simulated SSH brute-force attempts:



&#x20;   ssh socadmin@<target-ip>

&#x20;   # Enter wrong password multiple times



Generated logs:



&#x20;   Failed password for socadmin from 192.168.72.1 port 63276 ssh2



\---



\## 🔍 Step 2 — Splunk Detection



\### Detection Query:



&#x20;   index=\* source="/var/log/auth.log" "Failed password"

&#x20;   | rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

&#x20;   | stats count by src\_ip, host

&#x20;   | where count >= 3



\### Detection Logic:

\- Extract source IP  

\- Count failed attempts  

\- Trigger if ≥ 3 attempts  



\---



\## 🚨 Step 3 — Splunk Alert Configuration



\- Alert Name: SSH Brute Force Detection  

\- Trigger Condition: Number of results > 0  

\- Schedule: Cron (\* \* \* \* \*) → every 1 minute  

\- Time Range: Last 15 minutes  

\- Action: Webhook  



\### Webhook URL:



&#x20;   http://192.168.72.1:5678/webhook/<n8n-id>



\---



\## 🔄 Step 4 — n8n Workflow



\### Trigger Node:

\- Webhook (POST)



\### Input Payload from Splunk:



&#x20;   {

&#x20;     "body": {

&#x20;       "result": {

&#x20;         "src\_ip": "192.168.72.1",

&#x20;         "host": "wazuh-siem",

&#x20;         "count": "4"

&#x20;       }

&#x20;     }

&#x20;   }



\---



\## 🌐 Step 5 — Threat Intelligence (VirusTotal)



\### HTTP Request Node:



\- Method: GET  



&#x20;   https://www.virustotal.com/api/v3/ip\_addresses/{{$json.body.result.src\_ip}}



\### Headers:



&#x20;   x-apikey: <YOUR\_API\_KEY>



\---



\## 📊 Sample Response:



&#x20;   "last\_analysis\_stats": {

&#x20;     "malicious": 0,

&#x20;     "suspicious": 0,

&#x20;     "harmless": 58,

&#x20;     "undetected": 36

&#x20;   }



\---



\## 🧠 Step 6 — Decision Logic (IF Node)



\### Condition:



&#x20;   {{$json.data.attributes.last\_analysis\_stats.malicious}} > 0



\---



\## 🚨 Step 7 — SOC Output



\### TRUE (Malicious)



&#x20;   {

&#x20;     "alert": "🚨 MALICIOUS IP DETECTED",

&#x20;     "ip": "192.168.72.1",

&#x20;     "malicious\_score": 2

&#x20;   }



\### FALSE (Clean)



&#x20;   {

&#x20;     "alert": "✅ IP NOT FLAGGED AS MALICIOUS",

&#x20;     "ip": "192.168.72.1",

&#x20;     "malicious\_score": 0

&#x20;   }



\---



\## 🧪 Final Test



Workflow Execution:



1\. Trigger SSH failed attempts  

2\. Splunk detects and fires alert  

3\. Webhook sends data to n8n  

4\. n8n queries VirusTotal  

5\. Decision logic applied  

6\. Output generated  



\---



\## 🧠 Key Skills Demonstrated



\- SIEM Detection Engineering (Splunk)  

\- Log Analysis (Linux auth.log)  

\- Regex Field Extraction  

\- Alert Engineering \& Scheduling  

\- Webhook Integration  

\- SOAR Workflow Automation (n8n)  

\- Threat Intelligence Enrichment  

\- Conditional Logic (Automated Triage)  



\---



\## 💡 SOC Relevance



This project simulates real SOC workflow:



\- Alert ingestion  

\- IOC extraction  

\- Threat intelligence enrichment  

\- Automated triage  

\- Decision-based escalation  



\---



\## 🚀 Future Improvements



\- Integrate Slack / Email alerts  

\- Add AbuseIPDB + multi-source enrichment  

\- Auto-block IP using firewall (UFW)  

\- Create incident tickets (Jira simulation)  

\- Store logs in SIEM / database  



\---



\## 🏁 Conclusion



This project demonstrates a \*\*complete SOC automation pipeline\*\* from detection to enrichment and classification. It reflects real-world \*\*SOAR capabilities\*\* and showcases practical skills required for \*\*SOC Analyst / Detection Engineer roles\*\*.

