# =====================================================
# Block Sign-In via Microsoft Graph PowerShell
# - Blocks a single user (UPN) or many from a CSV
# - Optional: revoke existing refresh tokens (force reauth)
# - Adds a clear confirmation step before changing anything
# - Writes a simple execution log
# Requires: Microsoft.Graph PowerShell SDK
#   Install-Module Microsoft.Graph -Scope CurrentUser
# =====================================================

#requires -Version 5.1
#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions

[CmdletBinding()]
param(
    # EITHER: a single UPN (e.g., alice@contoso.com)
    # OR: a CSV path when -FromCsv is used (CSV must have column: UserPrincipalName)
    [Parameter(Mandatory=$true)]
    [string]$User,

    # Use this if you work in multi-tenant shells; otherwise omit
    [string]$TenantId,

    # Treat -User as a CSV file path with header "UserPrincipalName"
    [switch]$FromCsv,

    # Also revoke refresh tokens after blocking sign-in
    [switch]$RevokeSessions,

    # Where to write a simple log
    [string]$LogPath = "$(Join-Path $PSScriptRoot 'Block-SignIn.log')"
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "$(Get-Date -Format s) [$Level] $Message"
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch { }
}

function Connect-GraphSafe {
    param([string]$TenantId)
    try { $null = Get-MgContext } catch { }
    $ctx = $null
    try { $ctx = Get-MgContext } catch { }

    if (-not $ctx) {
        $connectParams = @{
            Scopes    = @('User.ReadWrite.All')   # Needed to update accountEnabled
            NoWelcome = $true
        }
        if ($TenantId) { $connectParams['TenantId'] = $TenantId }
        Connect-MgGraph @connectParams
    }
}

function Get-UserList {
    if ($FromCsv) {
        if (-not (Test-Path $User)) {
            throw "CSV not found: $User"
        }
        $rows = Import-Csv -Path $User
        if (-not $rows -or -not ($rows | Get-Member -Name UserPrincipalName -MemberType NoteProperty)) {
            throw "CSV must contain a column named 'UserPrincipalName'."
        }
        return ($rows | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)
    }
    else {
        return @($User)
    }
}

# -------------------------
# Main
# -------------------------
Write-Log "Starting Block-SignIn. Log: $LogPath"
Connect-GraphSafe -TenantId $TenantId
$targets = Get-UserList

if (-not $targets -or $targets.Count -eq 0) { throw "No users to process." }

Write-Host ""
Write-Host "About to BLOCK sign-in for the following account(s):" -ForegroundColor Yellow
$targets | ForEach-Object { Write-Host " - $_" }
if ($RevokeSessions) { Write-Host "`nRefresh tokens will be revoked after blocking." -ForegroundColor Yellow }

$confirmation = Read-Host "`nType 'BLOCK' to proceed"
if ($confirmation -ne 'BLOCK') {
    Write-Log "Aborted by user before making changes." "WARN"
    return
}

foreach ($upn in $targets) {
    try {
        Write-Log "Blocking sign-in for $upn ..."
        # Set accountEnabled = false
        Update-MgUser -UserId $upn -AccountEnabled:$false -ErrorAction Stop
        Write-Log "accountEnabled set to false for $upn."

        if ($RevokeSessions) {
            try {
                Revoke-MgUserSignInSession -UserId $upn -ErrorAction Stop
                Write-Log "Revoked refresh tokens for $upn."
            }
            catch {
                Write-Log "Failed to revoke tokens for $upn: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    catch {
        Write-Log "Failed to block sign-in for $upn: $($_.Exception.Message)" "ERROR"
    }
}

Write-Host ""
Write-Log "Completed Block-SignIn."
Write-Host "Done. Review the log at: $LogPath"