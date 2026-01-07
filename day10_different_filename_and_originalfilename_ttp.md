# Name
Masquerading Original filename does not match current filename

# Description
This analytic identifes instances where the original filename does not match the current filename. I have excluded some folders that make this noisy and added global file prevalence enrichment to reduce false postives. This is low fidelity and canno't be used as a detection alone.

# References
- https://redcanary.com/threat-detection-report/techniques/rename-system-utilities/
- https://attack.mitre.org/techniques/T1036/003/
- https://attack.mitre.org/techniques/T1036/
- https://attack.mitre.org/techniques/T1036/005/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Akira
- Carbanak
- Turla
- Bumblebee
- Darkhotel
- FIN7
- FIN13
- Volt Typhoon
- APT1
- APT28
- APT29
- APT32
- APT39
- APT41
- APT42
- APT5

# MITRE ATT&CK
- T1036.005: Masquerading: Match Legitimate Resource Name or Location
- T1036.003: Masquerading: Rename Legitimate Utilities
- T1036: Masquerading

# Data Sources
- Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query

```
let exclusions = datatable (exclusion:string)["excludedfile1.exe"];
DeviceProcessEvents
| extend filename=tolower(FileName)
| extend originalfilename=tolower(ProcessVersionInfoOriginalFileName)
| where filename !~ originalfilename and isnotempty(originalfilename)
| where not ( FolderPath has_any (@":\Program Files",@":\Windows") ) and FileName !in~ (exclusions)
| invoke FileProfile(SHA1, 1000)
| project Timestamp,FolderPath, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine,GlobalPrevalence,GlobalLastSeen,
Signer,SignatureState, ThreatName,Publisher

```
