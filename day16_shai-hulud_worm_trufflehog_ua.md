# Name
Shai-Hulud Worm - TruffleHog UserAgent (AWSCloudTrail)

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
- AWS
  - AWSCloudtrail

# Query

```
AWSCloudTrail 
| where EventName =~ "GetCallerIdentity" and UserAgent =~ "TruffleHog"
| distinct TimeGenerated, EventName, UserIdentityUserName, RequestParameters, SourceIpAddress, UserAgent
| sort by TimeGenerated asc

```
