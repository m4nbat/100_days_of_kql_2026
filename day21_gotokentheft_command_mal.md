# Name


# Description
The GoTokenTheft utility is a tool for stealing access tokens. Written in GoLang and deployed at C:\Users\<user>\Desktop\go.exe, it may be used to steal tokens to run commands with elevated privileges:

``` eee.ico REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f ```

# References
- 

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- 

# MITRE ATT&CK
- 
- 

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

```
//Indicators: eee.ico REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
Table
| Query .....

```
