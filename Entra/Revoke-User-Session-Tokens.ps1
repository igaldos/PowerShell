<# 
.SYNOPSIS
Revoke user sign-in sessions for a specified user in Azure Entra (Azure AD).
.DESCRIPTION
This script connects to Microsoft Graph for the specified tenant and revokes all sign-in sessions for a given user.
.PARAMETER UserId
The user ID (ObjectId or UserPrincipalName) of the user whose sessions will be revoked.
.PARAMETER TenantId
The Azure AD tenant ID to connect to.
.PARAMETER Scopes
The scopes required for the Microsoft Graph API. Defaults to 'User.RevokeSessions.All', 'User.ReadWrite.All', and 'Directory.ReadWrite.All'.
.EXAMPLE    
.\Revoke-User-Session-Tokens.ps1 -UserId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#>
function Invoke-RevokeUserSessions {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][ValidateNotNullOrEmpty()][string]$UserId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
        [Parameter()][string[]]$Scopes = @(
            'User.RevokeSessions.All',
            'User.ReadWrite.All',
            'Directory.ReadWrite.All'
        )
    )

    # 1) Ensure execution policy (optional; consider removing)
    # Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -ErrorAction Stop

    # 2) Install & import Graph modules
    foreach ($mod in 'Microsoft.Graph','Microsoft.Graph.Beta') {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Verbose "Installing $mod"
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module $mod -ErrorAction Stop
    }

    # 3) Connect
    try {
        Write-Verbose "Connecting to Microsoft Graph for tenant $TenantId"
        Connect-MgGraph -Scopes $Scopes -TenantId $TenantId -ErrorAction Stop
    } catch {
        Write-Error "Connection failed: $_"
        return
    }

    # 4) Revoke sessions
    if ($PSCmdlet.ShouldProcess($UserId, 'Revoke sign‑in sessions')) {
        try {
            Revoke-MgUserSignInSession -UserId $UserId -ErrorAction Stop
            Write-Host "✅ Successfully revoked sessions for $UserId." -ForegroundColor Green
        } catch {
            Write-Error "Failed to revoke sessions: $_"
        }
    }
}