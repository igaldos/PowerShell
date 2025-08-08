#requires -Version 5.1
#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

param(
    [Parameter(Mandatory)]
    [string]$TenantId
)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users          -ErrorAction Stop

function Connect-GraphSafe {
    [CmdletBinding()] param([string]$TenantId)
    try { $null = Get-MgContext } catch { }
    $needConnect = $true
    try {
        $ctx = Get-MgContext
        if ($ctx -and $ctx.Scopes -and ($ctx.Scopes -contains 'User.ReadWrite.All') -and $ctx.TenantId -eq $TenantId) {
            $needConnect = $false
        }
    } catch { }
    if ($needConnect) {
        Connect-MgGraph -Scopes 'User.ReadWrite.All' -TenantId $TenantId -NoWelcome | Out-Null
    }
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Script,[int]$MaxRetries=3,[int]$BaseDelaySeconds=2)
    for ($i=0; $i -le $MaxRetries; $i++) {
        try { return & $Script } catch {
            if ($i -eq $MaxRetries -or $_.Exception.Message -notmatch '429|5\d{2}') { throw }
            Start-Sleep -Seconds ([math]::Pow($BaseDelaySeconds, $i+1))
        }
    }
}

function Get-UserProperties {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Alias('UPN')][string]$UserPrincipalName)
    $u = Get-MgUser -UserId $UserPrincipalName -Property DisplayName,Department,JobTitle,OfficeLocation,Mail,OnPremisesSyncEnabled,Id
    if (-not $u) { throw "User not found: $UserPrincipalName" }
    [pscustomobject]@{
        UserPrincipalName     = $UserPrincipalName
        ObjectId              = $u.Id
        DisplayName           = $u.DisplayName
        Department            = $u.Department
        JobTitle              = $u.JobTitle
        OfficeLocation        = $u.OfficeLocation
        Mail                  = $u.Mail
        OnPremisesSyncEnabled = [bool]$u.OnPremisesSyncEnabled
    }
}

function Test-UserUpdateInputs {
    [CmdletBinding()] param([string]$Department,[string]$JobTitle,[string]$OfficeLocation)
    if ($Department     -and $Department.Length     -gt 64)  { throw "Department exceeds 64 characters." }
    if ($JobTitle       -and $JobTitle.Length       -gt 128) { throw "Job Title exceeds 128 characters." }
    if ($OfficeLocation -and $OfficeLocation.Length -gt 128) { throw "Office Location exceeds 128 characters." }
}

function Set-MgUserProfile {
    <#
      .SYNOPSIS  Update Department/JobTitle/OfficeLocation for a single user (with validation, diff, retry, and confirmation).
      .EXAMPLE   Set-MgUserProfile -TenantId TENANT-GUID -UserPrincipalName user@contoso.com -Department 'IT'
      .EXAMPLE   Set-MgUserProfile -TenantId TENANT-GUID -Interactive
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Alias('UPN')]
        [string]$UserPrincipalName,

        [string]$Department,
        [string]$JobTitle,
        [string]$OfficeLocation,

        [switch]$Interactive
    )

    Connect-GraphSafe -TenantId $TenantId

    # If interactive, prompt for UPN and fields when missing
    if ($Interactive) {
        if (-not $UserPrincipalName) { $UserPrincipalName = Read-Host 'Enter user email address' }
        try { $current = Get-UserProperties -UserPrincipalName $UserPrincipalName } catch { throw }
        Write-Host "`nCurrent user info for $($current.DisplayName):" -ForegroundColor Cyan
        "{0,-18} {1}" -f 'Department:',      $current.Department      | Out-Host
        "{0,-18} {1}" -f 'Job Title:',       $current.JobTitle        | Out-Host
        "{0,-18} {1}" -f 'Office Location:', $current.OfficeLocation  | Out-Host

        if (-not $Department)     { $Department     = Read-Host 'Enter new Department (blank = keep)' }
        if (-not $JobTitle)       { $JobTitle       = Read-Host 'Enter new Job Title (blank = keep)' }
        if (-not $OfficeLocation) { $OfficeLocation = Read-Host 'Enter new Office Location (blank = keep)' }
    }

    if (-not $UserPrincipalName) { throw "UserPrincipalName is required (or use -Interactive)." }

    Test-UserUpdateInputs -Department $Department -JobTitle $JobTitle -OfficeLocation $OfficeLocation

    $user = Get-MgUser -UserId $UserPrincipalName -Property Department,JobTitle,OfficeLocation,DisplayName,OnPremisesSyncEnabled,Id
    if (-not $user) { throw "User not found: $UserPrincipalName" }
    if ($user.OnPremisesSyncEnabled) { throw "User '$UserPrincipalName' is directory-synced. Update on-prem AD." }

    $desired = [ordered]@{}
    if ($PSBoundParameters.ContainsKey('Department')     -and $Department     -ne $user.Department)     { $desired.Department     = $Department }
    if ($PSBoundParameters.ContainsKey('JobTitle')       -and $JobTitle       -ne $user.JobTitle)       { $desired.JobTitle       = $JobTitle }
    if ($PSBoundParameters.ContainsKey('OfficeLocation') -and $OfficeLocation -ne $user.OfficeLocation) { $desired.OfficeLocation = $OfficeLocation }

    if ($desired.Count -eq 0) {
        return [pscustomobject]@{
            UserPrincipalName = $UserPrincipalName
            Status            = 'NoChange'
            Updated           = $false
            UpdatedProperties = @{}
            Message           = 'All values already match.'
        }
    }

    if ($Interactive) {
        Write-Host "`nPlanned changes:" -ForegroundColor Yellow
        $desired.GetEnumerator() | ForEach-Object { "  - {0}: {1}" -f $_.Key, $_.Value | Out-Host }
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Update properties: $($desired.Keys -join ', ')")) {
        Invoke-WithRetry -Script { Update-MgUser -UserId $UserPrincipalName -BodyParameter $desired }
        return [pscustomobject]@{
            UserPrincipalName = $UserPrincipalName
            ObjectId          = $user.Id
            Status            = 'Updated'
            Updated           = $true
            UpdatedProperties = $desired
        }
    }
}

function Find-UserUpn {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Query,[int]$Top=5)
    $p = @{
        ConsistencyLevel='eventual'; CountVariable='cnt'
        Top=[Math]::Min([Math]::Max($Top,1),25)
        Filter="startsWith(displayName,'$Query') or startsWith(userPrincipalName,'$Query') or startsWith(mail,'$Query')"
        Select='displayName,userPrincipalName,mail,id'
    }
    Get-MgUser @p | Select-Object DisplayName,UserPrincipalName,Mail,Id
}

Write-Host 'Script loaded: Set-MgUserProfile, Get-UserProperties, Find-UserUpn' -ForegroundColor Green

# Examples:
# Set-MgUserProfile -TenantId 'TENANT-GUID' -UserPrincipalName 'user@contoso.com' -Department 'IT'
# Set-MgUserProfile -TenantId 'TENANT-GUID' -Interactive
# Find-UserUpn 'nicole' | ft
