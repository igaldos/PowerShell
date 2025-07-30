# PowerShell Scripts

## Overview

A collection of reusable PowerShell scripts and functions designed to help system administrators and IT professionals automate common tasks—ranging from exporting BitLocker keys and managing Azure AD objects to deploying software agents.

## Features

- **Modular scripts** that can be run standalone or imported as modules  
- **Pipeline‑friendly** cmdlets with `-WhatIf` and `-Confirm` support  
- **Built‑in logging** and verbose output for auditability  
- **Cross‑platform compatibility**: PowerShell Core (7+) and Windows PowerShell (5.1)  
- **Secure credential handling** via `Get-Credential` or managed identities  

## Prerequisites

- **PowerShell 5.1** or newer (Windows PowerShell / PowerShell Core)  
- **Module dependencies** (e.g. Microsoft.Graph, Az, ActiveDirectory) installed via PSGallery  
