\# Phase 8 — Day 2  

\# SPL Detection Engineering



\## Overview



Day 2 focused on using Splunk Search Processing Language (SPL) from a detection engineering perspective. The objective was to move beyond simple log visibility and begin building SOC-style detection logic using Linux authentication telemetry already ingested into Splunk from /var/log/auth.log.



The work centered on identifying authentication attack patterns, extracting meaningful security fields from raw log data, building threshold-based detections for SSH brute-force behavior, identifying repeated sudo privilege activity, and creating investigation-oriented SPL queries that simulate real SOC workflows.



This phase demonstrated how raw Linux logs can be transformed into structured detections and analyst investigation views using SPL field extraction, time bucketing, and statistical aggregation.



---



\# Environment



Platform: Splunk Enterprise  

Server: wazuh-siem  

Log Source: /var/log/auth.log  

Primary Telemetry: Linux authentication and privilege activity logs  

Detection Focus: SSH authentication abuse and sudo privilege escalation activity



---



\# Day 2 Objectives



• Understand SPL from a detection engineering perspective  

• Build authentication attack detection queries  

• Detect SSH brute-force login attempts  

• Detect suspicious sudo privilege escalation activity  

• Build SOC-style detection queries using SPL  

• Simulate detection engineering workflows in Splunk



---



\# Detection Engineering Workflow



\## 1. Validation of SSH Failure Telemetry



The first step was confirming that failed SSH login events were present in Splunk and searchable. This verified that the ingestion pipeline created on Day 1 remained operational and that authentication telemetry was available for detection engineering.



Validation query:



index=main source="/var/log/auth.log" "Failed password"



This confirmed that the authentication logs contained key information needed for detection engineering including usernames, source IP addresses, hosts, and SSH failure messages.



---



\## 2. Field Extraction Using SPL



The next step was extracting important security fields from the raw logs. Because Linux logs are unstructured, regex-based extraction was used to create usable fields for detection engineering.



Username extraction from SSH failures:



index=main source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+)"



Source IP extraction:



index=main source="/var/log/auth.log" "Failed password"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"



sudo user extraction:



index=main source="/var/log/auth.log" "sudo:"

| rex "sudo:\\s+(?<user>\\S+)\\s+:"



sudo command extraction:



index=main source="/var/log/auth.log" "sudo:"

| rex "COMMAND=(?<command>.\*)"



These extractions allowed raw logs to be converted into structured data fields that could be counted, grouped, and analyzed.



---



\# SPL Detections Developed



\## 1. Failed SSH Login Count by User and Source IP



The first structured detection query counted failed SSH login attempts by username and source IP.



Query:



index=main source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<user>\\S+)"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count by user src\_ip

| sort - count



Detection value:



• Identifies high-volume failed login attempts  

• Highlights targeted user accounts  

• Shows attacking source IP addresses  

• Helps identify password guessing attempts



---



\## 2. SSH Brute Force Detection



The next detection introduced threshold-based detection logic using a time window.



Query:



index=main source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<username>\\S+)"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| bucket \_time span=5m

| stats count by \_time src\_ip username host

| where count >= 3

| sort - \_time - count



Detection logic:



• Groups activity into five minute time windows  

• Counts failed login attempts from the same source IP  

• Filters activity exceeding three failures



SOC relevance:



This query models a basic brute-force authentication detection commonly implemented in SOC environments.



---



\## 3. sudo Privilege Activity Visibility



Next, privilege activity was investigated by extracting sudo activity from authentication logs.



Query:



index=main source="/var/log/auth.log" "sudo:"

| rex "sudo:\\s+(?<user>\\S+)\\s+:"

| rex "COMMAND=(?<command>.\*)"

| stats count values(command) as commands by user host

| sort - count



Detection value:



• Identifies which accounts are executing privileged commands  

• Shows which commands are executed via sudo  

• Helps detect suspicious administrative activity



---



\## 4. Suspicious sudo Burst Detection



The sudo activity was then converted into a threshold-based detection.



Query:



index=main source="/var/log/auth.log" "sudo:"

| rex "sudo:\\s+(?<user>\\S+)\\s+:"

| rex "COMMAND=(?<command>.\*)"

| bucket \_time span=10m

| stats count values(command) as commands by \_time user host

| where count >= 3

| sort - \_time - count



Detection logic:



• Detects bursts of sudo activity within ten minutes  

• Identifies repeated privilege execution by a user  

• Highlights potentially suspicious administrative activity



SOC relevance:



Repeated privilege activity within a short time window may indicate attacker activity after gaining access.



---



\# Investigation Workflow Query



To simulate SOC investigation workflows, a combined timeline query was created to show both failed SSH authentication attempts and sudo activity.



Query:



index=main source="/var/log/auth.log" ("Failed password" OR "sudo:")

| rex "Failed password for (invalid user )?(?<failed\_user>\\S+)"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| rex "sudo:\\s+(?<sudo\_user>\\S+)\\s+:"

| rex "COMMAND=(?<command>.\*)"

| table \_time host process failed\_user src\_ip sudo\_user command \_raw

| sort - \_time



Investigation value:



• Displays authentication failures and privilege activity in one timeline  

• Helps analysts pivot between authentication abuse and administrative activity  

• Provides raw event context for deeper investigation



---



\# Final Detection Query



A refined brute-force detection was created that summarizes targeted users during suspicious login activity.



Query:



index=main source="/var/log/auth.log" "Failed password"

| rex "Failed password for (invalid user )?(?<username>\\S+)"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| bucket \_time span=5m

| stats count values(username) as targeted\_users by \_time src\_ip host

| where count >= 3

| sort - count



Detection improvements:



• Groups attacks by source IP  

• Shows which accounts were targeted  

• Applies threshold detection logic  

• Produces a cleaner SOC detection output



This query represents a portfolio-ready detection that could be operationalized as a scheduled Splunk alert or correlation search.



---



\# Technical Skills Practiced



• SPL query construction  

• Regex field extraction using rex  

• Authentication attack detection engineering  

• Time window detection logic using bucket  

• Event aggregation using stats  

• Privilege escalation monitoring  

• SOC investigation query development  

• Transforming raw logs into structured detections



---



\# Key Learning Outcomes



Day 2 shifted the focus from simply searching logs to building actual detection logic.



Instead of asking "Can I see the logs?" the focus became:



• What behavior indicates an attack?  

• What fields must be extracted for detection?  

• What thresholds represent suspicious activity?  

• What queries help analysts investigate alerts quickly?



By the end of the lab, Linux authentication logs were successfully transformed into structured detection logic using SPL.



---



\# Operational Outcome



By completing Day 2:



• Splunk was successfully used for detection engineering against Linux security logs  

• SSH brute-force detection logic was developed  

• sudo privilege activity monitoring was implemented  

• investigation workflow queries were created  

• a portfolio-quality SPL detection was produced



---



\# Conclusion



Phase 8 Day 2 demonstrated how Splunk can be used as a practical SOC detection engineering platform. Using Linux authentication telemetry, the lab progressed from raw log visibility to structured field extraction, authentication abuse detection, privilege activity monitoring, and SOC investigation workflows.



This stage strengthens core SOC skills in SPL detection logic, telemetry parsing, and investigation design, preparing the environment for Phase 8 Day 3 where Splunk will be used for SOC investigations and dashboard creation.

