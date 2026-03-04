\# SOC Operational Skills Mini-Lab  

\## Day 1 — Phishing Email Investigation



This lab simulates a real \*\*Security Operations Center (SOC) phishing investigation workflow\*\* including header analysis, authentication verification, IOC extraction, and analyst reporting.



The objective is to replicate how SOC analysts investigate suspicious emails reported by users.



---



\# Lab Environment



Existing SOC Lab Infrastructure:



\- Wazuh SIEM deployed

\- Windows Endpoint with Sysmon telemetry

\- Suricata IDS integrated

\- Microsoft Sentinel lab completed (KQL detections and investigations)

\- Hybrid detection engineering portfolio completed



This mini-lab focuses on \*\*SOC operational investigation skills rather than detection engineering\*\*.



---



\# Investigation Scenario



A suspicious email claiming to be from \*\*Microsoft Security\*\* was received requesting account verification due to unusual sign-in activity.



The email contained a link directing the user to verify their account.



Subject:



```

URGENT: Microsoft Account Security Alert

```



Email Content:



```

Dear User,



We detected unusual sign-in activity from a new location.



To secure your Microsoft account immediately, please verify your identity using the link below:



https://secure-microsoft-login-check.com/verify



Failure to verify within 24 hours may result in account suspension.



Microsoft Security Team

```



---



\# SOC Investigation Workflow



The investigation followed a structured SOC process:



1\. Evidence collection

2\. Email header analysis

3\. Sender infrastructure identification

4\. Authentication verification (SPF / DKIM / DMARC)

5\. IOC extraction

6\. Reputation analysis

7\. Analyst verdict and response recommendations



---



\# Email Header Analysis



Key findings from header analysis:



Sender Email:

```

muhammadhuraira177@gmail.com

```



Sending Mail Server:

```

mail-lj1-f177.google.com

```



Source IP:

```

209.85.208.177

```



This indicates the email was sent using \*\*Google's mail infrastructure\*\*.



---



\# Authentication Results



Authentication mechanisms were verified from the headers.



| Authentication Method | Result |

|----------------------|--------|

| SPF | Pass |

| DKIM | Pass |

| DMARC | Pass |



Interpretation:



The email was legitimately sent through Gmail infrastructure and \*\*not spoofed\*\*.



However, phishing campaigns frequently use legitimate email services.



---



\# IOC Extraction



Indicators of Compromise identified during investigation:



| IOC Type | Value | Source | Notes |

|---------|------|------|------|

| Email Address | muhammadhuraira177@gmail.com | Header | Sender email |

| IP Address | 209.85.208.177 | Received Header | Sending infrastructure |

| Domain | secure-microsoft-login-check\[.]com | Email Body | Microsoft impersonation domain |

| URL | hxxps://secure-microsoft-login-check\[.]com/verify | Email Body | Credential harvesting link |



All malicious indicators are \*\*defanged\*\* to prevent accidental interaction.



---



\# Reputation Analysis



VirusTotal reputation checks were performed.



Results:



Sending IP:

```

209.85.208.177

```



Detection Results:



```

Malicious: 0

Suspicious: 0

Harmless: Multiple

```



Interpretation:



The IP belongs to \*\*Google mail servers\*\*, which are legitimate.



Phishing actors commonly abuse trusted email providers to distribute malicious emails.



---



\# Phishing Indicators Identified



Multiple social engineering indicators were present:



\### Urgency



```

URGENT

Failure to verify within 24 hours

```



\### Fear-based messaging



```

Unusual sign-in activity detected

Account suspension warning

```



\### Brand impersonation



The email claims to be from \*\*Microsoft Security Team\*\* but was sent from \*\*Gmail infrastructure\*\*.



\### Suspicious domain



```

secure-microsoft-login-check.com

```



This domain attempts to impersonate Microsoft's authentication services.



Legitimate Microsoft authentication domains include:



```

login.microsoftonline.com

microsoft.com

live.com

```



---



\# SOC Analyst Verdict



Classification:



\*\*Phishing Email (Credential Harvesting Attempt)\*\*



Confidence Level:



\*\*High\*\*



Reasoning:



\- Social engineering language

\- Fake Microsoft login domain

\- Credential harvesting attempt

\- Brand impersonation

\- Suspicious URL



---



\# Recommended SOC Actions



Containment Actions:



\- Block domain  

```

secure-microsoft-login-check.com

```



\- Block phishing URL



\- Search email gateway logs for similar messages



Detection Improvements:



\- Implement domain impersonation detection rules

\- Monitor newly registered domains impersonating Microsoft



User Awareness:



\- Educate users about credential phishing

\- Encourage reporting of suspicious emails



---



\# Skills Demonstrated



SOC investigation workflow  

Email header analysis  

Authentication verification (SPF, DKIM, DMARC)  

IOC extraction and defanging  

Threat intelligence enrichment  

Phishing detection techniques  

SOC investigation reporting



---



\# Portfolio Value



This lab demonstrates practical \*\*SOC Tier 1 investigation skills\*\* including:



\- Email triage

\- Threat intelligence enrichment

\- IOC identification

\- Security incident documentation



These are core responsibilities of SOC analysts in real security operations environments.

