# Name
CastleLoader and CastleRAT Scheduled Task Detection

# Description
Detects the execution of 'schtasks.exe' being used to create a new task where the task payload involves Rundll32.exe.

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

Threats
- CastleRAT
- CastleLoader
- TAG150

# MITRE Techniques
- T1053.005 Scheduled Task/Job: Scheduled Task

# Query

```

//CastleLoader and CastleRAT - Commandline Detections
// TAG150
// Detects the execution of 'schtasks.exe' being used to create a new task where the task payload involves Rundll32.exe.
DeviceProcessEvents
  | where FileName =~ "schtasks.exe"
  // Check for the creation flag
  | where ProcessCommandLine has_any ("/create", "-create")
  // Check for the malicious payload trigger
  | where ProcessCommandLine has "rundll32"
  | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256

```
