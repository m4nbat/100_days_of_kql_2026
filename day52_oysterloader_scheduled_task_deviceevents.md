# Name
OysterLoader - Scheduled Task Creation via DeviceEvents (Broomstick)

# Description
Detects indicators associated with OysterLoader (aka Broomstick/CleanUpLoader). This malware typically arrives via SEO poisoning impersonating legitimate software (e.g., PuTTY, Teams). This query monitors the ScheduledTaskCreated action type in DeviceEvents and parses the task content to identify tasks executing rundll32.exe with suspicious DLLs in AppData directories, a key persistence mechanism for OysterLoader.

# References
- https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
- https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Oysterloader.AO!MTB

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- OysterLoader
- Broomstick
- CleanUpLoader
- Rhysida Ransomware (Affiliate Loader)

# MITRE ATT&CK
- T1053.005: Scheduled Task/Job: Scheduled Task
- T1218.011: System Binary Proxy Execution: Rundll32

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceEvents

# Query

```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ScheduledTaskCreated"
// Perform string search on the dynamic field first for performance
| where AdditionalFields has "rundll32" and AdditionalFields has "AppData"
// Parse the JSON to extract specific fields for clearer analysis
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend TaskContent = tostring(parse_json(AdditionalFields).TaskContent)
// Double check the extracted content (Optional, but ensures the keywords are in the right place)
| where TaskContent has "rundll32" and TaskContent has "AppData"
| project Timestamp, DeviceName, AccountName, TaskName, TaskContent, InitiatingProcessFileName, AdditionalFields
```