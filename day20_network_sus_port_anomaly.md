# Name
Anomaly Detection Hunt: External Network Connection - Unusual Port 

# Description
This detection analytic looks for external network connections to unusual ports which could indicate suspicious or malicious activity within the environment.

# References
- https://redcanary.com/threat-detection-report/techniques/powershell/

# Author
- M4nbat
- TomW

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
| where RemoteIPType =~ "Public" and RemotePort in~ (3389,22,23,5000,51,990,21,1337,4444,5555,6666,7777)
| make-series ConnectionCount = count() on Timestamp from ago(30d) to now() step 1d by DeviceName
| render timechart 

```

# Example Output

<img width="1423" height="399" alt="image" src="https://github.com/user-attachments/assets/fd675843-7bbd-4c72-ac49-10440c893a86" />
