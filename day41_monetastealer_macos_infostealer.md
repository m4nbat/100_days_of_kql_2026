# Name
MonetaStealer macOS Information Stealer

# Description
Detects behaviors associated with the MonetaStealer malware on macOS. This threat disguises itself as a Windows executable (e.g., Portfolio_Review.exe) to trick users but executes a Mach-O binary. It performs extensive discovery (Chrome history, Keychain dumps, wireless network listing) and exfiltrates data via Telegram API. It specifically targets "Crypto", "Wallet", and financial keywords in document files.

# References
- https://www.knowyouradversary.ru/2026/01/369-heres-how-monetastealer-abuses.html
- https://the-sequence.com/monetastealer-threat (Analysis of PyInstaller/Mach-O structure)

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- MonetaStealer

# MITRE ATT&CK
- T1036.005 (Masquerading: Match Legitimate Name or Location - Note: Uses .exe extension on macOS)
- T1555.001 (Credentials from Password Stores: Keychain)
- T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)
- T1056.002 (Input Capture: GUI Input Capture - Note: Clipboard theft)
- T1020 (Automated Exfiltration)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceFileEvents

# Query

## Query 1: Suspicious ".exe" Execution on macOS (Masquerading)
Detects the execution of a file ending in .exe on a macOS device, a key characteristic of MonetaStealer's social engineering tactic.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
let MacOS_Devices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
DeviceProcessEvents
// Filter for macOS devices
| where DeviceId in~ (MacOS_Devices)
| where FileName endswith ".exe"
// MonetaStealer often runs from user profiles (Downloads/Desktop)
| where FolderPath has_any ("Users", "Downloads", "Desktop")
```

## Query 2: MonetaStealer Discovery Commands (Behavioral)
Detects the sequence of specific discovery commands used by MonetaStealer: dumping keychain, listing wifi networks, and reading clipboard.

```kql
let MacOS_Devices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
DeviceProcessEvents
// Filter for macOS devices
| where DeviceId in~ (MacOS_Devices)
// Filter for macOS commands used by MonetaStealer
| where (FileName =~ "security" and ProcessCommandLine has "find-generic-password")
     or (FileName =~ "networksetup" and ProcessCommandLine has "-listpreferredwirelessnetworks")
     or (FileName =~ "pbpaste")
// Group by device to find multiple distinct discovery actions in a short window
| summarize DistinctActions = dcount(FileName), Actions = make_set(ProcessCommandLine) by DeviceName, bin(Timestamp, 15m)
| where DistinctActions >= 2
```

## Query 3: Exfiltration to Telegram API (Network)
Detects the exfiltration of the staged zip file (STOLEN{sessionID}.zip) to the Telegram API, which MonetaStealer uses as a C2 channel.

```kql
let MacOS_Devices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
DeviceNetworkEvents
// Filter for macOS devices
| where DeviceId in~ (MacOS_Devices)
| where RemoteUrl has "api.telegram.org"
// Correlation with a process that isn't a browser or standard telegram app can be high signal
| where InitiatingProcessFileName !in~ ("Google Chrome", "Safari", "Firefox", "Telegram", "Telegram Desktop")
```
