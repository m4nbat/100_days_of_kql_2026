# Name
CastleLoader and CastleRAT Scheduled Task Detection

# Description
Detects PowerShell execution to impair defences - Windows Defender exclusions

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
- T1564.012 Hide Artifacts: File/Path Exclusions
- T1562 : Impair Defenses
  - T1562.001 Impair Defenses: Disable or Modify Tools 

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query

```

//CastleLoader and CastleRAT - Commandline Detections
// TAG150
// New Botnet Emerges from the Shadows: NightshadeC2 | eSentire
DeviceProcessEvents
| where InitiatingProcessCommandLine has_all ("-Force","Add-MpPreference","-ExclusionProcess","C:","Users")

```
