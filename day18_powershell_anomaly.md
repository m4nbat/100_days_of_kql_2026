# Name
Anomaly Detection Hunt - PowerShell External Connections

# Description
This detection analytic looks for the execution of powershell.exe with external network connections whisch could indicate suspicious or malicious activity within the environment.

# References
- https://redcanary.com/threat-detection-report/techniques/powershell/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- 

# MITRE ATT&CK
- T1059.001 Command and Scripting Interpreter: PowerShell 
- T1059 Command and Scripting Interpreter

# Data Sources
- M365 Defender
  - DeviceNetworkEvents

# Query

```
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe" , "pwsh.exe" ) and RemoteIPType =~ "Public"
| make-series ProcessCount = count() on Timestamp from ago(30d) to now() step 1d by DeviceName
| render timechart 

```

# Example Output

<img width="601" height="172" alt="image" src="https://github.com/user-attachments/assets/16f84d4d-7682-42c4-abe6-b937d06d240d" />
