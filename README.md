# PowerShell Scripts

## Overview

A collection of reusable PowerShell scripts and functions designed to help system administrators and IT professionals automate common tasks—ranging from exporting BitLocker keys and managing Azure AD objects to deploying software agents.

## Features

- **Modular scripts** that can be run standalone or imported as modules  
- **Pipeline‑friendly** cmdlets with `-WhatIf` and `-Confirm` support  
- **Built‑in logging** and verbose output for auditability  
- **Cross‑platform compatibility**: PowerShell Core (7+) and Windows PowerShell (5.1)  
- **Secure credential handling** via `Get-Credential` or managed identities  


## Prerequisites & Dependencies

- **PowerShell 5.1** (Windows) or **PowerShell 7+** (cross-platform)
- **Required modules:**
  - `Microsoft.Graph` (for Entra/Intune scripts)
  - `Az` (for Azure resource management, if needed)
  - `ActiveDirectory` (for on-premises AD tasks)
  - `ExchangeOnlineManagement` (for Exchange Online scripts)
  - Other modules as noted in script comments
- Install modules from the PowerShell Gallery using:
  ```powershell
  Install-Module Microsoft.Graph, Az, ActiveDirectory, ExchangeOnlineManagement -Scope CurrentUser
  ```
- Some scripts may require admin rights or specific permissions in Azure/Intune/Exchange environments.

### Execution Policy

If you encounter script execution errors, you may need to set the execution policy:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Importing Modules

If a script does not automatically import required modules, you can do so manually:
```powershell
Import-Module Microsoft.Graph
Import-Module Az
Import-Module ActiveDirectory
Import-Module ExchangeOnlineManagement
```

## Script Directory Structure

### Entra
- `Create-Temporary-Pass.ps1` — Create temporary passwords for users in Entra ID (Azure AD)
- `Export-Entra-App-Registrations.ps1` — Export application registrations from Entra ID
- `Reset-PW-Revoke-Sessions.ps1` — Reset user passwords and revoke sessions in Entra ID
- `Revoke-User-Session-Tokens.ps1` — Revoke user session tokens in Entra ID

### ExchangeOnline
- `Disable-Welcome-Message.ps1` — Disable the welcome message for new Exchange Online mailboxes

### Intune
- `Export-BitLocker-Keys.ps1` — Export BitLocker recovery keys from Intune-managed devices
- `Sync-Intune-Devices.ps1` — Force device sync in Microsoft Intune

### Software
- `Install-SentinelOne_64bit.ps1` — Install SentinelOne agent (64-bit)

---
For usage instructions, see comments within each script. Contributions and improvements are welcome!
