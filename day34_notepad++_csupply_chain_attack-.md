
# Name
Notepad++ Supply Chain Compromise (Lotus Blossom / Chrysalis)

# Description
Detects indicators of the 2025/2026 Notepad++ supply chain attack where the update mechanism (WinGUp) was hijacked to deliver the Chrysalis backdoor. The detection strategy focuses on three key behaviors:

Malicious Updater Behavior: gup.exe spawning suspicious child processes or dropping files in unusual locations.

DLL Side-Loading: The specific abuse of BluetoothService.exe loading log.dll (a known infection chain technique).

Network IOCs: Connections to known C2 infrastructure associated with the Lotus Blossom campaign.

# References
- https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
- https://socradar.io/blog/notepad-infrastructure-hijacked/
- https://doublepulsar.com/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Lotus Blossom
- Billbug, Spring Dragon, Thrip)
- Violet Typhoon
- Zirconium
- Chrysalis Backdoor

# MITRE ATT&CK
- T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
- T1574.002 (Hijack Execution Flow: DLL Side-Loading)
- T1071.001 (Application Layer Protocol: Web Protocols)

# Data Sources
- Microsoft Defender for Endpoint
      - DeviceProcessEvents
      - DeviceImageLoadEvents
      - DeviceNetworkEvents
      - DeviceFileEvents

# Queries

## Query 1: Identify impacted versions of Notepad++ running in the environment

```
let version = dynamic(["8.8.9", "8.9", "8.9.1"]);
let vul_ver=
DeviceProcessEvents
| where ActionType contains "ProcessCreated"
| where InitiatingProcessVersionInfoInternalFileName contains "notepad++.exe"
| where (InitiatingProcessVersionInfoProductVersion has_any (version))
// distinct DeviceName // uncomment this line to view impacted devices

```

## Query 2: Suspicious Notepad++ Updater (GUP) Behavior
This query identifies ```gup.exe``` (the Notepad++ updater) spawning unexpected child processes or executing files from the TEMP directory, which mimics the behavior of the malicious ```update.exe``` payload.

```
// Detects gup.exe launching suspicious child processes or payloads in TEMP
DeviceProcessEvents
| where InitiatingProcessFileName =~ "gup.exe" or InitiatingProcessVersionInfoOriginalFileName =~ "gup.exe"
// Filter out legitimate installer behavior (usually spawns npp.*.installer.exe)
| where not(FileName matches regex @"npp\.\d+\..+\.Installer\.exe")
| where not(FileName =~ "cmd.exe" and ProcessCommandLine has " /c del ") // Standard cleanup
| extend Suspicion = case(
    FileName =~ "update.exe", "High - Malicious Installer Name",
    FileName =~ "AutoUpdater.exe", "High - Malicious Installer Name",
    FolderPath has "AppData\\Local\\Temp", "Medium - Execution from Temp",
    "Low - Non-Standard Child"
)
```


## Query 3: Chrysalis DLL Side-Loading (BluetoothService + log.dll)
The attack utilizes a legitimate Bitdefender binary (```BluetoothService.exe```) to side-load a malicious DLL named ```log.dll```. This combination is highly anomalous.

```
// Detects the specific DLL side-loading chain used by Chrysalis
DeviceImageLoadEvents
| where FileName =~ "log.dll"
| where InitiatingProcessFileName =~ "BluetoothService.exe" 
// Verify if the initiating process is running from a suspicious location (not Program Files)
| extend ProcessPath = tostring(InitiatingProcessFolderPath)
| where ProcessPath !startswith "C:\\Program Files" and ProcessPath !startswith "C:\\Windows\\System32"
```


## Query 4: Network Connection to Known Lotus Blossom IOCs
Detects network connections to the specific IP addresses and domains identified in the campaign (redirected update servers and C2s).

```
// Detects connections to Lotus Blossom / Chrysalis C2 infrastructure
let MaliciousIPs = dynamic([
    "95.179.213.0",
    "45.76.155.202",
    "45.32.144.255"
]);
let MaliciousDomains = dynamic([
    "api.skycloudcenter.com",
    "temp.sh" // Used for recon data exfiltration via curl
]);
DeviceNetworkEvents
| where RemoteIP in (MaliciousIPs) or RemoteUrl has_any (MaliciousDomains)
```

## Query 5: Reconnaissance Activity (Curl to Temp.sh)
The malware uses ```curl.exe``` to send reconnaissance data (whoami, tasklist) to ```temp.sh```.

```
// Detects curl sending data to temp.sh (High Fidelity for this campaign)
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where ProcessCommandLine has "temp.sh"

```


