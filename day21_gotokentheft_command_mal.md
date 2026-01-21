# Name
GoTokenTheft utility commandline - disable RestrictedAdmin

# Description
The GoTokenTheft utility is a tool for stealing access tokens. Written in GoLang and deployed at C:\Users\<user>\Desktop\go.exe, it may be used to steal tokens to run commands with elevated privileges. The threat actor disables RestrictedAdmin for Remote Desktop Protocol (RDP) to obtain credentials for remoting into other devices:

``` eee.ico REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f ```

# References
- https://blog.talosintelligence.com/uat-8837/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- UAT-8837
- GoTokenTheft

# MITRE ATT&CK
- T1562 : Impair Defenses
- 

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

```
//Indicators: eee.ico REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
DeviceProcessEvents
| where ProcessCommandLine has_all ("REG","ADD",@"HKLM\System\CurrentControlSet\Control\Lsa","DisableRestrictedAdmin","REG_DWORD","00000000")

```
