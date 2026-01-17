# Name
Shai-Hulud Worm - TruffleHog Commandline

# Description
The prolific “Shai-Hulud” worm made a noisy return on November 24, 2025, compromising hundreds of npm packages in order to steal credentials, including popular packages from Zapier, ENS Domains, PostHog, and Postman. We detected this threat countless times across our customers in the hours and days that followed the initial compromise. While we’re continuing to monitor the situation, things have slowed enough that we wanted to share some additional information on how we detected the Shai-Hulud threats, how we helped numerous security teams respond to these threats, and how organizations can harden their security posture against similar threats moving forward.

# References
- https://redcanary.com/blog/threat-detection/shai-hulud-worm/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Shai-Hulud Worm

# MITRE ATT&CK
- T1213.003 Data from Information Repositories: Code Repositories
- T1213 Data from Information Repositories
- Collection

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

# 1

```
// Execution of TruffleHog via Bun
// The use of the Bun JavaScript runtime to execute TruffleHog, a tool used to search for secrets in code repositories.
DeviceProcessEvents
| where FileName in~ ("bun","bun.exe") and ProcessCommandLine contains "trufflehog"

```

# 2

```
// Execution of Shai Hulud-related commands
// A process executing with a command line indicative of SHA1HULUD.
DeviceProcessEvents
| where ProcessCommandLine has_all ("sha1hulud","--name","github")

```

# 3

```
// GitHub runner listener process being executed from a user
// The execution of the GitHub runner listener process from a user path (it’s usually as part of a CI/CD pipeline).
DeviceProcessEvents
| where FileName =~ "runner.listener" and ProcessCommandLine has_all ('configure','--unattended','--url','github.com','--name') and FolderPath contains "users" 

```

