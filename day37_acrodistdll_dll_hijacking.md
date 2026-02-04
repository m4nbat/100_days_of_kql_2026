# Possible DLL Hijacking of acrodistdll.dll

## Description
Detects possible DLL hijacking of `acrodistdll.dll` by monitoring image load events. The detection triggers when this specific DLL is loaded from a path that does not match the standard Adobe Acrobat installation directories (`C:\Program Files\Adobe\...` or `C:\Program Files (x86)\Adobe\...").

## References
- https://hijacklibs.net/entries/3rd_party/adobe/acrodistdll.html

## Author
M4nbat (Logic adapted from Pokhlebin Maxim)

## Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

## Threats
- Generic DLL Hijacking
- Adobe Acrobat Exploitation

## MITRE ATT&CK
- T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking

## Data Sources
- Microsoft Defender for Endpoint
- DeviceImageLoadEvents

## Detection Query

### Query 1 — Microsoft Defender XDR (Advanced Hunting)

```kql
// Focus on image load events for the specific Adobe DLL
DeviceImageLoadEvents
| where Timestamp > ago(24h)
| where FileName =~ "acrodistdll.dll"
// Extend to normalize pathing for comparison
| extend LoadPath = tolower(FolderPath)
// Exclude legitimate Adobe installation paths (both 64-bit and 32-bit)
| where not (LoadPath matches regex @"^c:\\program files( \\((x86)\\))?\\adobe\\acrobat .+\\acrobat\\acrodistdll\\.dll$")
// Project relevant fields for investigation
| project Timestamp, 
          DeviceName, 
          FileName, 
          FolderPath, 
          SHA256, 
          InitiatingProcessFileName, 
          InitiatingProcessCommandLine, 
          InitiatingProcessParentFileName
| sort by Timestamp desc
```

## Engineering & Performance Breakdown
- Platform Specifics: This query targets the `DeviceImageLoadEvents` table in Microsoft Defender. This table is high-volume, so filtering by `FileName` immediately is the most performant approach.

- Regex vs. Multiple Filters: The rule uses a case-insensitive regex `matches regex` to consolidate the exclusion of both `Program Files` and `Program Files (x86)` paths. This makes the query cleaner and more resilient to different Acrobat versions (e.g., Acrobat DC, Acrobat 2020).

- Path Normalization: In KQL, it is best practice to use `tolower()` or the case-insensitive operator `=~` when dealing with file paths, as attackers may use mixed casing to bypass simple string matches.

- False Positive Note: As noted in the original Sigma rule, this is highly effective but may trigger on "Portable" versions of Adobe tools or custom enterprise deployments that install Adobe software to a non-standard drive (e.g., `D:\Apps\`). If your environment uses a non-standard drive, modify the regex to account for other drive letters.

## Investigation Steps
If this query returns results:

- Check the signer of the DLL (you can join with `DeviceFileCertificateInfo` using the SHA1/SHA256).
- Examine the `InitiatingProcessFileName`. If `cmd.exe` or `powershell.exe` is loading this DLL from a Temp folder, it is high-priority.
- Verify the prevalence of the file in your environment. Genuine hijacks usually occur on a single machine or a small cluster before spreading.