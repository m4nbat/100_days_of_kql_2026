# Name
DDoSIA Config Threat Feed Rule

# Description
Quick external lookup query to grab DDoSIA configs from an external source

# References
- https]//witha.]name/data/last.json

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- NoName
- DDoSIA

# MITRE ATT&CK
- T1498 : Network Denial of Service

# Data Sources
- Defender for Endpoin
- Microsoft Sentinel
- Azure Data Explorer

# Query

```
let raw_json = external_data(json_data: string) [@"https://witha.name/data/last.json"] with (format='raw');
raw_json
| extend parsed_data = parse_json(json_data)  // Convert the string into JSON
| extend targets_array = parsed_data.targets  // Extract the "targets" array
| mv-expand targets_array                    // Expand array into individual rows
| extend target_ip = tostring(targets_array.ip),
         target_host = tostring(targets_array.host),
         target_path = tostring(targets_array.path)
| project target_ip, target_host, target_path
| distinct target_host

```





