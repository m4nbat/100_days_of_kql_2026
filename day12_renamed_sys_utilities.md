# Name
Masquerading - renamed system utility

# Description
This analytic identifes instances where system utilities have been renamed to masquerade as something else.

## Weeding out false positives
Looking for process names (e.g., regsvr32.exe) outside of expected paths will generate false positives because many software developers bundle specific versions of a system process. For example, we often run into false positives on rundll32’s unexpected paths for certain antivirus software. Identify any tools that exhibit this behavior and add them as exclusions to your toolset.

Because anyone can name a process whatever they want, you might see false positives on process names that are not the actual system utility. Cross reference internal name information to avoid tripping on a random process named rundll32 instead of the real rundll32 that was relocated or renamed.

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
- Qbot
- Mimikatz
- Bondat
- Cobalt Strike
- SocGholish
- Emotet

# MITRE ATT&CK
- T1036.005: Masquerading: Match Legitimate Resource Name or Location
- T1036.003: Masquerading: Rename Legitimate Utilities
- T1036: Masquerading

# Data Sources
- Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query

```
let renamedTools = datatable (filename:string)["psexec.exe","rundll32","rclone.exe","mimikatz.exe","powershell.exe","cmd.exe","msbuild.exe",regsvr32.exe","certutil.exe","vncviewer.exe","rclone.exe","wscript.exe",7zip.exe,"adexplorer.exe","procdump.exe"]; //add more to this list of commonly renamed tools or LOLBINS
DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName has_any (renamedTools) and ( InitiatingProcessVersionInfoOriginalFileName !~ InitiatingProcessFileName )

```
