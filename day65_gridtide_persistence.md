# Name
GRIDTIDE - Registry Modification for Persistence (Run Keys / Hidden Attributes)

# Description
Global espionage campaigns often establish persistence on compromised hosts by modifying Windows Registry Run keys or using system configurations to hide malicious binaries. This query detects attempts to add suspicious executables to auto-run locations.

# References
- https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign

# Author
- M4nbat

Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

Threats
- GRIDTIDE
- UNC2814

MITRE ATT&CK
- T1037 (Boot or Logon Initialization Scripts)
- T1547.001 (Registry Run Keys / Startup Folder)

Data Sources
- Microsoft Defender XDR
   - DeviceRegistryEvents

# Query
## Query 1

```kql
let DeviceRegistryEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    RegistryKey: string,
    RegistryValueName: string,
    RegistryValueData: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    AccountName: string
)
[
    // Case 1: Malicious run key added
    datetime(2024-02-25 12:30:00), "device-guid-1", "Workstation01.contoso.com", "RegistryValueSet", 
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "WindowsUpdateSys", 
    "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\winupd.exe", "powershell.exe", "powershell.exe -c Set-ItemProperty...", "jdoe",
    
    // Case 2: Normal run key update
    datetime(2024-02-25 13:00:00), "device-guid-2", "Laptop02.contoso.com", "RegistryValueSet",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive",
    "C:\\Program Files\\Microsoft OneDrive\\onedrive.exe /background", "onedrive.exe", "onedrive.exe", "SYSTEM"
];
// Usage: Detect suspicious binaries added to Registry Run keys (Common APT persistence)
let RunKeys = dynamic([
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
]);
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (RunKeys)
// Filter for suspicious paths in the registry value data
| where RegistryValueData has_any ("AppData", "Temp", "ProgramData", "Public")
| where RegistryValueData endswith ".exe" or RegistryValueData endswith ".dll" or RegistryValueData endswith ".bat" or RegistryValueData endswith ".vbs"
// Exclude known good processes to reduce noise
| where InitiatingProcessFileName !in~ ("msiexec.exe", "trustedinstaller.exe")
```
| project Timestamp, DeviceName, AccountName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
