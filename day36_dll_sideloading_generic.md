# Name
Suspicious DLL Hijacking and Sideloading (HijackLibs Consolidated)

# Description
Detects the loading of DLLs that are frequently targeted for hijacking or sideloading (such as version.dll, shcore.dll, libvlc.dll, etc.) when they are loaded from non-standard directories or by suspicious processes. This query uses a "Known-Good" path exclusion logic based on the HijackLibs Sigma feed specifications.

# References
https://hijacklibs.net/

https://github.com/wietze/HijackLibs

# Author
M4nbat

# Socials
https://www.linkedin.com/in/grjk83/

@knappresearchlb

Threats
Generic Malware Sideloading

Earth Preta

APT29 (Cozy Bear)

Lazarus Group

MITRE ATT&CK
T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking

T1574.002 - Hijack Execution Flow: DLL Side-Loading

Data Sources (Microsoft XDR, Microsoft 365, Microsoft Azure etc. products and table names)
Microsoft Defender for Endpoint

DeviceImageLoadEvents

Query (1 or more KQL queries for the topic of the detection)
Query 1: Consolidated Image Load Detection (Defender XDR)
Code snippet
// Define a list of high-risk DLLs often used in sideloading/hijacking
let TargetedDLLs = pack_array(
    "libvlc.dll", "version.dll", "shcore.dll", "cryptbase.dll", 
    "userenv.dll", "dwmapi.dll", "uxtheme.dll", "propsys.dll", 
    "apphelp.dll", "profapi.dll", "dbghelp.dll", "winmm.dll"
);
DeviceImageLoadEvents
| where Timestamp > ago(24h)
// Filter for specific DLL names from the TargetedDLLs list
| where FileName in~ (TargetedDLLs)
| extend LoadPath = tolower(FolderPath)
// Exclude legitimate paths based on standard installation locations
| where not(LoadPath startswith @"c:\windows\system32\" 
         or LoadPath startswith @"c:\windows\syswow64\" 
         or LoadPath startswith @"c:\windows\winsxs\"
         or LoadPath startswith @"c:\program files\"
         or LoadPath startswith @"c:\program files (x86)\")
// Further filter: common technique is to place the DLL in a user-writable folder
| where LoadPath contains @"\users\" 
     or LoadPath contains @"\appdata\" 
     or LoadPath contains @"\temp\"
     or LoadPath matches regex @"^[a-z]:\\[^\\]+\.exe$" // Loaded from root or suspicious shallow path
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
Query 2: Specific VLC libvlc.dll Sideloading (Earth Preta Style)
Code snippet
// Specific detection for libvlc.dll hijacking often seen in Earth Preta campaigns
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "libvlc.dll"
| extend IsStandardPath = FolderPath startswith @"C:\Program Files\VideoLAN\VLC\" 
                       or FolderPath startswith @"C:\Program Files (x86)\VideoLAN\VLC\"
| where IsStandardPath == false
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
----------- Template End --------------
