\# Phase 8 — Day 3  

\# Splunk SOC Investigation \& Security Monitoring Dashboard



\## Overview



Day 3 focused on performing SOC-style investigations in Splunk using Security Information and Event Management (SIEM) telemetry collected from Linux authentication logs. The objective was to simulate how SOC analysts investigate authentication attacks, pivot between related activities, and visualize security events using Splunk dashboards.



Using Linux authentication logs (`/var/log/auth.log`), multiple investigation workflows were executed to analyze SSH authentication failures, attacker source IP behavior, targeted usernames, and privileged sudo activity. Structured SPL queries were used to extract fields, perform behavioral analysis, and create investigation timelines.



The final stage of the lab involved building a security monitoring dashboard in Splunk to visualize authentication abuse patterns and privileged activity within the environment.





---



\# Environment



\*\*SIEM Platform:\*\* Splunk Enterprise  

\*\*Server:\*\* wazuh-siem  

\*\*Operating System:\*\* Ubuntu Server  

\*\*Log Source:\*\* `/var/log/auth.log`  

\*\*Data Ingestion Method:\*\* Splunk File Monitoring  

\*\*Index:\*\* main  

\*\*Log Type:\*\* Linux Authentication Logs  





---



\# Investigation Workflow



SOC investigations typically begin with reviewing alert evidence and pivoting through related events to identify attacker behavior patterns.



The investigation process in this lab followed a typical SOC workflow:



1\. Identify authentication failure events

2\. Extract attacker source IP addresses

3\. Analyze targeted usernames

4\. Build attack timelines

5\. Investigate privilege escalation activity

6\. Correlate authentication abuse with privileged commands

7\. Summarize attacker activity patterns





---



\# SSH Authentication Failure Investigation



Initial analysis focused on identifying SSH authentication failures within the environment.



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| table \_time host source sourcetype \_raw

| sort \_time

```



This query retrieves raw SSH authentication failure events from the Linux authentication log.





---



\# Extracting Attacker IPs and Targeted Users



To enable investigation pivots, usernames and source IP addresses were extracted from the log events using regular expression parsing.



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| table \_time user src\_ip host

| sort \_time

```



This query extracts the following fields:



\- \*\*user\*\* → targeted account

\- \*\*src\_ip\*\* → source IP performing the authentication attempts





---



\# Attacker Behavior Analysis



Once fields were extracted, attacker behavior was analyzed by grouping events by source IP.



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count as failed\_attempts values(user) as targeted\_users by src\_ip

| sort - failed\_attempts

```



This analysis identifies:



\- the most active attacking source IP

\- the number of authentication failures

\- which usernames were targeted





---



\# Attack Timeline Investigation



After identifying suspicious source IP activity, a chronological timeline was created to analyze attack progression.



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| search src\_ip="ATTACKER\_IP"

| table \_time user src\_ip host

| sort \_time

```



This timeline allows SOC analysts to identify:



\- attack start time

\- attack frequency

\- targeted account patterns





---



\# Privileged Activity Investigation



Privilege escalation activity was investigated by analyzing `sudo` command execution events.



\### SPL Query



```

index="main" source="/var/log/auth.log" "sudo:"

| rex "sudo:\\s+(?<user>\\S+)\\s+:"

| table \_time user host \_raw

| sort \_time

```



This query identifies which users executed privileged commands and when those actions occurred.





---



\# SSH Failure and Privileged Activity Correlation



To simulate SOC investigation pivoting, authentication failures and sudo activity were correlated within the same investigation timeline.



\### SPL Query



```

index="main" source="/var/log/auth.log" ("Failed password" OR "sudo:")

| rex "Failed password for (invalid user )?(?<failed\_user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| rex "sudo:\\s+(?<sudo\_user>\\S+)\\s+:"

| eval activity\_type=case(searchmatch("Failed password"),"ssh\_failure", searchmatch("sudo:"),"sudo\_activity")

| table \_time activity\_type src\_ip failed\_user sudo\_user host \_raw

| sort \_time

```



This query allows analysts to observe authentication abuse events alongside privileged activity within a single investigation view.





---



\# SOC Triage Summary



A triage summary was created to quickly identify high-risk attacker activity.



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count as failed\_attempts dc(user) as unique\_users values(user) as targeted\_users earliest(\_time) as first\_seen latest(\_time) as last\_seen by src\_ip

| convert ctime(first\_seen) ctime(last\_seen)

| sort - failed\_attempts

```



This summary provides a clear overview of attacker behavior patterns.





---



\# Security Monitoring Dashboard



A Splunk security monitoring dashboard was created to visualize authentication attacks and privileged activity.



The dashboard includes the following panels.





---



\# Dashboard Panel 1 — Failed SSH Attempts Over Time



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| timechart span=5m count as failed\_ssh\_attempts

```



This visualization highlights bursts of SSH authentication attacks over time.





---



\# Dashboard Panel 2 — Top Attacker Source IPs



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count as failed\_attempts by src\_ip

| sort - failed\_attempts

```



This panel identifies the most active attacker source IP addresses.





---



\# Dashboard Panel 3 — Targeted Usernames



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count as failed\_attempts by user

| sort - failed\_attempts

```



This panel shows which accounts were targeted most frequently.





---



\# Dashboard Panel 4 — Sudo Activity Over Time



\### SPL Query



```

index="main" source="/var/log/auth.log" "sudo:"

| timechart span=5m count as sudo\_activity

```



This visualization provides visibility into privileged command execution activity.





---



\# Dashboard Panel 5 — Total Failed SSH Attempts



\### SPL Query



```

index="main" source="/var/log/auth.log" "Failed password"

| stats count as total\_failed\_ssh\_attempts

```



This panel provides a high-level metric summarizing authentication abuse volume.





---



\# Dashboard Panel 6 — Top Users Performing Sudo Activity



\### SPL Query



```

index="main" source="/var/log/auth.log" "sudo:"

| rex "sudo:\\s+(?<user>\\S+)\\s+:"

| stats count as sudo\_events by user

| sort - sudo\_events

```



This panel highlights which users executed privileged commands most frequently.





---



\# Skills Demonstrated



This lab demonstrates several important SOC analyst capabilities:



\- Splunk log ingestion and analysis

\- SPL-based detection engineering

\- Field extraction using regular expressions

\- Authentication attack investigation

\- Privileged activity monitoring

\- Security event correlation

\- SOC investigation workflow simulation

\- Security dashboard creation





---



\# Outcome



By the end of Phase 8 Day 3, Splunk was successfully used to simulate real SOC investigation workflows. Authentication abuse patterns were analyzed, attacker behavior was investigated, and a security monitoring dashboard was developed to visualize security telemetry.



This lab demonstrates practical experience with Splunk SIEM investigation workflows, SPL analytics, and security monitoring dashboard creation within a SOC environment.

