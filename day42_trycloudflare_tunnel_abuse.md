# Name
TryCloudflare Tunnel Abuse (Quick Tunneling)

# Description
Detects the initiation of "Quick Tunnels" via the cloudflared utility (often renamed) using the trycloudflare feature. This technique allows adversaries to expose local services (RDP, SMB, C2) to the internet through Cloudflare's infrastructure without an account, bypassing traditional inbound firewall rules. The detection looks for specific command-line arguments and DNS patterns associated with these ephemeral tunnels.

# References
- https://www.knowyouradversary.ru/2026/01/368-hunting-for-trycloudflare-abuse.html
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/trycloudflare/
- https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Unattributed Financially Motivated Groups (delivering XWorm, AsyncRAT, VenomRAT)
- BlueAlpha (GammaLoad)
- LABRAT (Cryptojacking)

# MITRE ATT&CK
- T1572 (Protocol Tunneling)
- T1090.003 (Proxy: Multi-hop Proxy)
- T1102 (Web Service: Bidirectional Communication)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceNetworkEvents
- Microsoft Sentinel
  - SecurityEvent
  - DnsEvents (if available)

# Query

## Query 1: Cloudflared Quick Tunnel Execution
Detects the execution of the cloudflared binary (or renamed variants) initiating a Quick Tunnel using the --url flag, which is characteristic of the TryCloudflare abuse.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceProcessEvents
// Filter for the standard binary name or common renames (attackers often rename it to look like system processes)
| where FileName =~ "cloudflared.exe" or FileName =~ "cloudflared-windows-amd64.exe" 
   or ProcessVersionInfoOriginalFileName =~ "cloudflared.exe"
// The '--url' flag is required for TryCloudflare (Quick Tunnels) to specify the local service to expose
| where ProcessCommandLine has "--url"
// Explicitly look for the absence of authentication flags (Quick Tunnels don't use 'tunnel run <UUID>')
| where not(ProcessCommandLine has "tunnel run" or ProcessCommandLine has "login")
// Optional: Detect exposure of sensitive ports like RDP (3389) or SSH (22)
| extend ExposedPort = extract(@"--url\s+.*:(\d+)", 1, ProcessCommandLine)
```

## Query 2: DNS Resolution of TryCloudflare Domains
Detects the specific DNS pattern associated with Quick Tunnels, where a randomly generated subdomain of trycloudflare.com is resolved.

```kql
// Microsoft Sentinel (DnsEvents / DeviceNetworkEvents)
// Note: Requires DNS logging visibility
let TryCloudflareDomains = dynamic(["trycloudflare.com"]);
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse" or ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (TryCloudflareDomains)
// Filter out legitimate business use if known (Quick Tunnels are rarely used in production)
```

## Query 3: Renamed Cloudflared Binary Execution
Detects the execution of cloudflared.exe when it has been renamed to evade detection, a common TTP in this campaign.

```kql
DeviceProcessEvents
// Identify by original filename in metadata, ignoring the on-disk filename
| where ProcessVersionInfoOriginalFileName =~ "cloudflared.exe"
// Alert if the current filename is NOT one of the standard names
| where not(FileName in~ ("cloudflared.exe", "cloudflared-windows-amd64.exe", "cloudflared-linux-amd64"))
```
