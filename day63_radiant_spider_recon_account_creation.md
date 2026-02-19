# Name
Radiant Spider (SilentSkimmer) - Reconnaissance, Discovery, and Suspicious Account Creation

# Description
This detection identifies reconnaissance and persistence activity associated with Radiant Spider (SilentSkimmer). It covers DNS-based out-of-band application security testing (OAST) callbacks to known domains (e.g., 1433.eu.org, dnslog.cn) via ping or nslookup, drive enumeration via fsutil, and the creation of a suspicious local account named asp.net$ which has been observed in Radiant Spider intrusions as a backdoor account.

# References
- https://www.crowdstrike.com/adversaries/radiant-spider/
- https://www.sleuthcon.com/radiant-spider-unveiled
- https://unit42.paloaltonetworks.com/silent-skimmer-latest-campaign/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- RADIANT SPIDER
- CL-CRI-0941
- SilentSkimmer

# MITRE ATT&CK
- T1136.001: Create Account: Local Account
- T1016: System Network Configuration Discovery

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents

# Query

## Query 4: Reconnaissance, Discovery, and Suspicious Account Creation

```kql
// Test Data Table
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    FileName: string,
    FolderPath: string,
    SHA256: string,
    ProcessCommandLine: string,
    ProcessId: long,
    AccountName: string,
    AccountDomain: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    InitiatingProcessId: long,
    InitiatingProcessParentFileName: string
)
[
    // Case 1: Ping to known OAST domain
    datetime(2026-02-19 13:00:00), "device-guid-4", "AppSrv01.contoso.com", "ProcessCreated", 
    "ping.exe", "C:\\Windows\\System32\\ping.exe", "e5f6a7b8...", 
    "ping test.1433.eu.org", 5566, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe /c ping test.1433.eu.org", 7788, "w3wp.exe",

    // Case 2: fsutil execution
    datetime(2026-02-19 13:05:00), "device-guid-4", "AppSrv01.contoso.com", "ProcessCreated", 
    "fsutil.exe", "C:\\Windows\\System32\\fsutil.exe", "f6a7b8c9...", 
    "fsutil fsinfo drives", 9900, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe /c fsutil fsinfo drives", 7788, "w3wp.exe",
    
    // Case 3: Suspicious user creation
    datetime(2026-02-19 13:10:00), "device-guid-4", "AppSrv01.contoso.com", "ProcessCreated", 
    "net.exe", "C:\\Windows\\System32\\net.exe", "a7b8c9d0...", 
    "net user asp.net$ P@ssw0rd123! /add", 1234, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe /c net user asp.net$...", 7788, "w3wp.exe"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
// Combine the three distinct recon/setup behaviors into one focused query
| where (FileName in~ ("nslookup.exe", "ping.exe") and ProcessCommandLine has_any("1433.eu.org", "dnslog.cn", "dnslog.myfw.us"))
   or (FileName =~ "fsutil.exe" and ProcessCommandLine has_all("fsinfo", "drives"))
   or (FileName in~ ("net.exe", "net1.exe") and ProcessCommandLine has "user" and ProcessCommandLine has "asp.net$")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```
