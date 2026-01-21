# Name
GoTokenTheft utility commandline - disable RestrictedAdmin

# Description
Post-compromise actions
UAT-8837 can exploit both n-day and zero-day vulnerabilities to gain access to target environments. Most recently, UAT-8837 exploited a ViewState Deserialization zero-day vulnerability in SiteCore products, CVE-2025-53690, to obtain initial access.

After UAT-8837 gains initial access, they begin conducting preliminary reconnaissance, leveraging the following commands:

```
ping google[.]com
tasklist /svc
netstat -aon -p TCP
whoami
quser
hostname
net user  
```

# References
- https://blog.talosintelligence.com/uat-8837/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- UAT-8837

# MITRE ATT&CK
- T1082 : System Information Discovery
- T1033 : System Owner/User Discovery 
- T1049 : System Network Connections Discovery
- T1087.001 Account Discovery: Local Account
- T1016.001 System Network Configuration Discovery: Internet Connection Discovery

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

```
let timeframe = 1h; 
let DiscoveryEvents = materialize ( DeviceProcessEvents | where Timestamp > ago(30d) 
// Filter for the relevant binaries first to reduce the dataset 
| extend DiscoveryCommand = case( ProcessCommandLine has "ping " and ProcessCommandLine has "google.com", "ping_google", ProcessCommandLine has "tasklist" and ProcessCommandLine has "/svc", "tasklist_svc", ProcessCommandLine has "netstat" and ProcessCommandLine has "-aon" and ProcessCommandLine has "-p" and ProcessCommandLine has "TCP", "netstat_recon", FileName =~ "whoami.exe", "whoami", FileName =~ "quser.exe", "quser", FileName =~ "hostname.exe", "hostname", (FileName in~ ("net.exe", "net1.exe")) and ProcessCommandLine has "user" and not(ProcessCommandLine has "/add" or ProcessCommandLine has "/delete"), "net_user", "none" ) 
| where DiscoveryCommand != "none" 
| project Timestamp, DeviceId, DeviceName, DiscoveryCommand, ProcessCommandLine, AccountName ); 
DiscoveryEvents 
| summarize FirstEvent = min(Timestamp), LastEvent = max(Timestamp), DistinctCommandsFound = dcount(DiscoveryCommand), CommandList = make_set(DiscoveryCommand), DetailedCommands = make_set(ProcessCommandLine) by DeviceId, DeviceName, AccountName, bin(Timestamp, timeframe) 
| where DistinctCommandsFound >= 6 
| project FirstEvent, LastEvent, DeviceName, AccountName, DistinctCommandsFound, CommandList, DetailedCommands

```
