# Name
Notepad++ Supply Chain Attack (Lotus Blossom/Chrysalis)

# Description
Detects behaviors associated with the February 2026 Notepad++ supply chain compromise. The attack involves the malicious redirection of the Notepad++ updater (gup.exe) to download a compromised installer ("Chrysalis"). Post-compromise activity includes DLL sideloading of Bitdefender components (BDSubWiz.exe), extensive reconnaissance using cmd.exe, and data exfiltration via curl.exe to temporary file-hosting services.

# References
- https://www.knowyouradversary.ru/2026/02/372-notepad-supply-chain-attack.html
- https://notepad-plus-plus.org/news/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Lotus Blossom
- Chrysalis
- APT32 (OceanLotus) - Note: Techniques overlap with historical OceanLotus tradecraft.

# MITRE ATT&CK
- T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
- T1574.002 (Hijack Execution Flow: DLL Side-Loading)
- T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
- T1041 (Exfiltration Over C2 Channel)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceNetworkEvents
- Microsoft Sentinel
  - SecurityEvent

# Query

## Query 1: Suspicious Curl Upload to Temp.sh (Exfiltration)
Detects the specific exfiltration method observed in this campaign where curl.exe is used to upload reconnaissance data to temp.sh.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "curl.exe"
// Filter for upload flags (-F) and the specific domain mentioned in intelligence
| where ProcessCommandLine has_all ("-F", "temp.sh") 
   or ProcessCommandLine has "file=@"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

## Query 2: Notepad++ Updater (gup.exe) Spawning Suspicious Children
Detects the Notepad++ updater process (gup.exe) launching unexpected child processes like cmd.exe, powershell.exe, or unknown installers, indicating a hijacked update flow.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "gup.exe" or InitiatingProcessVersionInfoOriginalFileName =~ "gup.exe"
// Allow-list legitimate child processes if known (e.g., notepad++.exe). 
// The malicious campaign spawns cmd.exe and other installers.
| where not(FileName =~ "notepad++.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

## Query 3: BDSubWiz DLL Sideloading (Renamed Bitdefender Component)
Detects the specific DLL sideloading technique where the legitimate Bitdefender BDSubWiz.exe is renamed (e.g., to BluetoothService.exe) to mask malicious activity.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceProcessEvents
| where Timestamp > ago(24h)
// Identify process by internal original name
| where ProcessVersionInfoOriginalFileName =~ "BDSubWiz.exe" 
// Alert if the on-disk file name does NOT match the original name
| where not(FileName =~ "BDSubWiz.exe")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine, FolderPath
```

## Query 4: Batch Reconnaissance Redirection
Detects a sequence of discovery commands (whoami, tasklist, systeminfo) being piped (>>) to a text file, a behavior observed in the Chrysalis infection chain.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has ">>" 
| where ProcessCommandLine has_any ("whoami", "tasklist", "systeminfo", "netstat", "ipconfig")
// Reduce noise by looking for the specific pattern of short text files often used in this campaign (e.g., a.txt)
| where ProcessCommandLine matches regex @">>\s*[\w]+\.txt"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
