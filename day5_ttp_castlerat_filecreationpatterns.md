# Name
CastleLoader and CastleRAT PowerShell File Naming Patterns

# Description
Detects PowerShell File Naming Patterns Created by CastleRAT

# References
- https://www.esentire.com/blog/new-botnet-emerges-from-the-shadows-nightshadec2
- https://www.darktrace.com/blog/castleloader-castlerat-behind-tag150s-modular-malware-delivery-system
- https://www.splunk.com/en_us/blog/security/castlerat-malware-detection-splunk-mitre-attck.html
- https://www.recordedfuture.com/research/from-castleloader-to-castlerat-tag-150-advances-operations
- https://www.recordedfuture.com/research/graybravos-castleloader-activity-clusters-target-multiple-industries

# Author
- M4nbat
  
# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- CastleRAT
- CastleLoader
- TAG150

# MITRE Techniques
- T1059.001 Command and Scripting Interpreter: PowerShell

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceFileEvents

# Query

```

//CastleLoader and CastleRAT - File Detections
// TAG150
// New Botnet Emerges from the Shadows: NightshadeC2 | eSentire
// Detect file patterns created by CastleRAT
// Low fidelity threat hunt query not for always on analytics
DeviceFileEvents
| where InitiatingProcessFolderPath has_all ("Users",@"AppData\Roaming") and FileName matches regex @"[a-zA-Z]+\.ps1"
| count | where Count > 0

```
