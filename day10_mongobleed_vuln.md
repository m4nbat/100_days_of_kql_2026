# Name
Query to identify internet facing devices and then find those running the MongoDB service with a version impacted by the MongoBleed vulnerability

# Description
Query to identify internet facing devices and then find those running the MongoDB service with a version impacted by the MongoBleed vulnerability

# References
- https://www.akamai.com/blog/security-research/cve-2025-14847-all-you-need-to-know-about-mongobleed
- https://www.mongodb.com/company/blog/news/mongodb-server-security-update-december-2025
- https://learn.microsoft.com/en-us/defender-endpoint/internet-facing-devices

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- MongoBleed

# MITRE ATT&CK
- Initial Access
-  T1210 : Exploitation of Remote Services
-  T1190 : Exploit Public-Facing Application

# Data Sources
- M365 Defender
  - DeviceInfo
  - DeviceNetworkEvents

# Query

```
let InternetFacingDevices =
DeviceInfo
| where IsInternetFacing = true // Find all devices that are internet-facing
| distinct DeviceId;
let PatchVersion = dynamic(["8.2.3", "8.0.17", "7.0.28", "6.0.27", "5.0.32", "4.4.30"]);
DeviceNetworkEvents
| where DeviceId in~ (InternetFacingDevices)
| where InitiatingProcessVersionInfoInternalFileName == "mongod.exe"
| where not (InitiatingProcessVersionInfoProductVersion has_any(PatchVersion))
| count | where Count > 0  // comment out or delete to see full fat results

```


