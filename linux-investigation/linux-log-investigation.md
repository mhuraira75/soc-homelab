\# Phase 7 — Linux Security Log Investigation (Wazuh SIEM)



\## Overview



This lab focuses on investigating Linux authentication and privilege activity using Wazuh SIEM. Linux servers are common targets for credential attacks such as SSH brute force and unauthorized privilege escalation. The objective of this exercise was to simulate suspicious Linux activity and perform a structured SOC-style investigation using real system logs ingested by Wazuh.



The investigation scenarios simulated common Linux attack patterns including authentication failures, successful logins following failed attempts, and privileged account creation using sudo.



---



\# Lab Environment



| Component | Technology |

|--------|--------|

| SIEM | Wazuh |

| Target System | Ubuntu Linux (Wazuh Manager) |

| Log Source | /var/log/auth.log |

| Monitoring Interface | Wazuh Dashboard |

| Attack Simulation | SSH authentication attempts \& sudo commands |



---



\# Scenario 1 — SSH Authentication Failure Investigation



\## Attack Simulation



Multiple SSH login attempts were made using a non-existent user account to simulate invalid user probing.



Example command used:



```

ssh fakeuser@localhost

```



Multiple incorrect passwords were entered to generate authentication failures.



\## Log Evidence



Example log entry from `/var/log/auth.log`:



```

Failed password for invalid user fakeuser from 127.0.0.1 port 51824 ssh2

```



\## Wazuh Detection



Wazuh successfully ingested the event and generated a security alert:



```

sshd: Failed password for invalid user fakeuser

```



\## Investigation Findings



| Field | Value |

|------|------|

Agent | wazuh-siem |

Target Username | fakeuser |

Source IP | 127.0.0.1 |

Service | sshd |

Attempts Observed | 4 |



\## MITRE ATT\&CK Mapping



Technique:  

\*\*T1110 — Brute Force\*\*



Tactic:  

\*\*Credential Access\*\*



---



\# Scenario 2 — Successful SSH Login After Failed Attempts



\## Activity Simulation



After generating authentication failures, a legitimate login was performed using a valid user account.



Example command:



```

ssh socadmin@<server-ip>

```



A successful login was performed followed by session termination.



\## Log Evidence



```

Accepted password for socadmin from 127.0.0.1 port 51902 ssh2

pam\_unix(sshd:session): session opened for user socadmin

```



\## Wazuh Detection



Wazuh captured the authentication success and session creation events.



\## Investigation Logic



SOC analysts correlate authentication failures followed by successful login events to detect possible credential compromise.



\### Event Timeline Example



```

Failed login — fakeuser

Failed login — fakeuser

Failed login — fakeuser

Failed login — fakeuser

Successful login — socadmin

SSH session opened

```



\## MITRE ATT\&CK Mapping



T1110 — Brute Force  

T1078 — Valid Accounts



---



\# Scenario 3 — Privileged Account Creation



\## Activity Simulation



A new user account was created using sudo to simulate privileged activity.



Command executed:



```

sudo useradd suspicioususer

```



Password was also assigned to the account.



```

sudo passwd suspicioususer

```



\## Log Evidence



Example log entry:



```

sudo: socadmin : USER=root ; COMMAND=/usr/sbin/useradd suspicioususer

```



\## Security Significance



Privileged account creation is a high-risk activity frequently associated with persistence techniques used by attackers after initial compromise.



\## Investigation Findings



| Field | Value |

|------|------|

User executing command | socadmin |

Privilege level | root (via sudo) |

Command | useradd |

Account created | suspicioususer |



\## MITRE ATT\&CK Mapping



Technique:  

\*\*T1136 — Create Account\*\*



Tactic:  

\*\*Persistence\*\*



---



\# Key SOC Investigation Skills Demonstrated



Linux authentication log analysis  

SSH brute force detection  

Correlation of failed and successful login activity  

Privilege escalation monitoring  

Account creation monitoring  

MITRE ATT\&CK mapping for Linux attacks  

Security event investigation using Wazuh SIEM



---



\# Conclusion



This lab demonstrates how Linux security telemetry can be analyzed within a SIEM to detect authentication attacks and suspicious privileged activity. By simulating common Linux attack patterns and investigating them through Wazuh, the exercise replicates real SOC investigation workflows used to monitor Linux servers in production environments.



This investigation expands the SOC home lab beyond Windows telemetry and strengthens multi-platform detection and investigation capability.

