\# Active Directory Attack Detection Lab (Splunk SIEM)



\## 📌 Overview

This project demonstrates the deployment of an enterprise-style Active Directory environment and the detection of authentication-based attacks using Splunk SIEM.



The lab simulates real-world SOC operations, including domain setup, user management, attack simulation, log forwarding, and detection engineering.



\---



\## 🧱 Lab Architecture



\- Domain Controller: Windows Server (DOM-CTRL-01)

\- Domain: company.local

\- Endpoint: Windows 11 (Domain-joined)

\- SIEM: Splunk (Ubuntu)

\- Log Forwarding: Splunk Universal Forwarder

\- Attack Simulation: Failed authentication attempts



\---



\## ⚙️ Step 1 — Domain Controller Setup



\- Installed Windows Server (Desktop Experience)

\- Configured static IP address

\- Renamed server to `DOM-CTRL-01`

\- Installed Active Directory Domain Services (AD DS)

\- Promoted server to Domain Controller

\- Created domain: `company.local`



\---



\## 👥 Step 2 — Active Directory Configuration



Created Organizational Units (OUs):

\- IT

\- HR

\- Employees



Created Users:

\- jdoe

\- asmith

\- itadmin



Created Group:

\- IT\_Admins



Assigned:

\- Added `itadmin` to `IT\_Admins` group



\---



\## 🖥️ Step 3 — Domain Join



\- Configured Windows 11 endpoint DNS to Domain Controller IP

\- Joined endpoint to domain `company.local`

\- Logged in as domain user: `COMPANY\\jdoe`



\---



\## 📊 Step 4 — Log Generation (Baseline Activity)



Performed normal user activity:

\- Multiple login and logout actions

\- Executed system commands (whoami, ipconfig)

\- Created files and directories



Observed:

\- Event ID 4624 → Successful logon events



\---



\## 🔥 Step 5 — Attack Simulation (Brute Force)



Simulated failed authentication attempts using SMB:



&#x20;   net use \\\\DOM-CTRL-01\\IPC$ /user:COMPANY\\fakeuser wrongpassword



Generated logs:

\- Event ID 4625 → Failed logon attempts

\- Event ID 4776 → NTLM authentication attempts



\---



\## 🔧 Step 6 — Enable Audit Logging



Configured audit policies using Group Policy:



Path:

Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies



Enabled:



\- Audit Logon → Success \& Failure

\- Audit Credential Validation → Success \& Failure

\- Audit Account Management → Success \& Failure



Applied policy using:



&#x20;   gpupdate /force



\---



\## 📡 Step 7 — Splunk Integration



Installed Splunk Universal Forwarder on Domain Controller.



Configured log forwarding:



File:

C:\\Program Files\\SplunkUniversalForwarder\\etc\\system\\local\\inputs.conf



Content:



&#x20;   \[WinEventLog://Security]

&#x20;   disabled = 0



Configured Splunk to receive logs on port:

9997



\---



\## 🔍 Step 8 — Detection in Splunk



\### Basic Log Search



&#x20;   index=main sourcetype=WinEventLog:Security



\---



\### Failed Login Detection



&#x20;   index=main (EventCode=4625 OR EventCode=4776)



\---



\### Brute Force Detection



&#x20;   index=main (EventCode=4625 OR EventCode=4776)

&#x20;   | stats count by Account\_Name, src\_ip

&#x20;   | sort -count



\---



\### Suspicious Activity Detection



&#x20;   index=main (EventCode=4625 OR EventCode=4776)

&#x20;   | stats count by Account\_Name

&#x20;   | where count > 5



\---



\## 🧠 Key Findings



\- Active Directory centralises authentication logs on the Domain Controller

\- Failed authentication attempts generate Event ID 4625

\- NTLM authentication attempts generate Event ID 4776

\- Repeated failed login attempts indicate potential brute-force attacks

\- SIEM tools can be used to detect and correlate suspicious authentication behaviour



\---



\## 🎯 SOC Relevance



This project demonstrates:



\- Active Directory monitoring

\- Authentication log analysis

\- Brute-force attack detection

\- SIEM log ingestion and analysis

\- Detection engineering using Splunk SPL

\- Real-world SOC investigation workflow



\---



\## 🚀 Conclusion



This lab replicates a real enterprise Security Operations Center (SOC) environment by integrating Active Directory with SIEM-based detection.



It provides hands-on experience in detecting, analysing, and responding to authentication-based attacks, which are critical skills for SOC Analysts and Detection Engineers.

