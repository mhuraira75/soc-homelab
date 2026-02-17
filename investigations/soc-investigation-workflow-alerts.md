\# SOC Investigation Workflow — Behaviour Chain Analysis



\## Objective



Practice SOC alert queue prioritisation and investigation ordering using real telemetry.



\## Scenario



Multiple alerts triggered within a short timeframe representing simulated attack behaviour.



\## Investigation Approach



1\. Prioritised alerts based on attacker intent rather than alert order.

2\. Started investigation with defense evasion (log clearing).

3\. Pivoted to persistence mechanisms.

4\. Analysed execution behaviour via certutil LOLBin usage.

5\. Investigated potential lateral movement.

6\. Confirmed single-origin behaviour chain via PowerShell parent process.



\## Behaviour Chain Identified



Execution → Persistence → Defense Evasion → Lateral Movement



\## Key SOC Skills Practiced



\- Alert prioritisation strategy

\- Noise vs signal identification

\- Timeline reconstruction

\- Parent-child process analysis

\- Attack lifecycle recognition



