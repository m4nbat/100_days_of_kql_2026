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

# Threats
- CastleRAT
- CastleLoader
- TAG150

# MITRE Techniques
- T1053.005 Scheduled Task/Job: Scheduled Task

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceEvents

# Query

```

//CastleLoader and CastleRAT - Commandline Detections
// TAG150
// Detects the execution of 'schtasks.exe' being used to create a new task where the task payload involves Rundll32.exe.
DeviceEvents
  | where ActionType == "ScheduledTaskCreated"
  // Optimization: Filter for rundll32 before expensive parsing
  | where AdditionalFields has "rundll32"
  // Level 1 Parsing: Extract the outer JSON
  | extend BaseJson = parse_json(AdditionalFields)
  // Level 2 Parsing: The 'TaskContent' field is a stringified JSON that must be parsed again
  | extend TaskContent = parse_json(tostring(BaseJson.TaskContent))
  // Extract specific fields from the nested structure (Actions -> Exec -> Command)
  | extend TaskName = tostring(BaseJson.TaskName)
  | extend Command = tostring(TaskContent.Actions.Exec.Command)
  | extend Arguments = tostring(TaskContent.Actions.Exec.Arguments)
  // Final filter on the extracted fields
  | where Command has "rundll32" or Arguments has "rundll32"
    | project TimeGenerated, MachineGroup, DeviceName, ActionType, Command, Arguments, InitiatingProcessAccountName, AdditionalFields

```
