<#
.SYNOPSIS
    Resets user security by forcing password change and revoking all active sessions.

.DESCRIPTION
    This script connects to Microsoft Graph to perform security reset operations on a specified user:
    - Forces password change at next sign-in
    - Revokes all existing user sessions across all devices

.PARAMETER UserUPN
    User Principal Name (email address) of the target user. If not provided, script will prompt interactively.

.PARAMETER Force
    Skip confirmation prompt. Useful for automation scenarios.

.EXAMPLE
    .\Reset-PW-Revoke-Sessions.ps1
    Interactive mode - prompts for UPN and confirmation

.EXAMPLE
    .\Reset-PW-Revoke-Sessions.ps1 user@contoso.com
    Reset security for specified user with confirmation

.EXAMPLE
    .\Reset-PW-Revoke-Sessions.ps1 user@contoso.com -Force
    Reset security for specified user without confirmation prompt

.AUTHOR
    Ignacio Galdos

.VERSION
    1.1

.NOTES
    Requires Microsoft.Graph PowerShell module and User.ReadWrite.All permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, Position=0, HelpMessage="User Principal Name (e.g., user@domain.com)")]
    [string]$UserUPN,
    
    [Parameter(Mandatory=$false, HelpMessage="Skip confirmation prompt")]
    [switch]$Force
)

# Check if Microsoft Graph module is available
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Error "Microsoft Graph PowerShell module not found. Install with: Install-Module Microsoft.Graph -Force -AllowClobber"
    exit 1
}

# Function to validate UPN format
function Test-UPNFormat {
    param([string]$UPN)
    return $UPN -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
}

# Get UPN from parameter or prompt interactively
if ([string]::IsNullOrWhiteSpace($UserUPN)) {
    do {
        $UserUPN = Read-Host -Prompt 'Enter user UPN'
        if ([string]::IsNullOrWhiteSpace($UserUPN)) {
            Write-Host "UPN cannot be empty." -ForegroundColor Red
            continue
        }
        if (-not (Test-UPNFormat -UPN $UserUPN)) {
            Write-Host "Invalid UPN format. Use: user@domain.com" -ForegroundColor Red
            continue
        }
        break
    } while ($true)
} else {
    if (-not (Test-UPNFormat -UPN $UserUPN)) {
        Write-Error "Invalid UPN format: '$UserUPN'"
        exit 1
    }
}

# Confirmation (unless -Force is used)
if (-not $Force) {
    Write-Host "`nWARNING: This will force password change and revoke all sessions for '$UserUPN'" -ForegroundColor Yellow
    $confirmation = Read-Host "Continue? (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Host "Operation cancelled."
        exit 0
    }
}

try {
    # Authenticate to Microsoft Graph
    Connect-MgGraph -Scopes "User.ReadWrite.All" -ErrorAction Stop

    # Verify user exists
    $user = Get-MgUser -UserId $UserUPN -ErrorAction Stop

    # Force password change at next sign-in
    Update-MgUser -UserId $UserUPN -PasswordProfile @{
        ForceChangePasswordNextSignIn = $true
    } -ErrorAction Stop

    # Revoke all user sessions
    Revoke-MgUserSignInSession -UserId $UserUPN -ErrorAction Stop

    Write-Host "Security reset completed for '$UserUPN'" -ForegroundColor Green

} catch {
    Write-Error "Failed to complete security reset for '$UserUPN': $($_.Exception.Message)"
    exit 1
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}