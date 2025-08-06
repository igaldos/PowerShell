<#
.SYNOPSIS
Exports all Azure Entra (Azure AD) application registrations and their service principals for a specified tenant to a CSV file.

.DESCRIPTION
Connects to Microsoft Graph for the given tenant, retrieves all application registrations and their associated service principals, and exports the details to a CSV file.

.PARAMETER TenantId
The Azure AD tenant ID to connect to.

.PARAMETER OutputPath
The path to the CSV file to export results. Defaults to '.\AzureAD-AppRegistrations-All.csv'.

.EXAMPLE
.\Export-Entra-App-Registrations.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [string]$OutputPath = '.\AzureAD-AppRegistrations-All.csv'
)

# Ensure Microsoft.Graph SDK is available
if (-not (Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph

# Interactive login against a specific tenant
Disconnect-MgGraph -Force -ErrorAction SilentlyContinue
Connect-MgGraph -TenantId $TenantId `
               -Scopes Application.Read.All,Directory.Read.All `
               -UseDeviceCode

# Build a lookup table of Service Principals
$spLookup = @{}
Get-MgServicePrincipal -All -Property Id,AppId |
    ForEach-Object { $spLookup[$_.AppId] = $_ }

# Fetch Applications and join to SPs
$results = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,PublicClient |
    ForEach-Object {
        $sp = $spLookup[$_.AppId]
        [PSCustomObject]@{
            DisplayName         = $_.DisplayName
            AppId               = $_.AppId
            ApplicationObjectId = $_.Id
            CreatedDateTime     = $_.CreatedDateTime
            IsPublicClient      = ($_.PublicClient -ne $null)
            ServicePrincipalId  = $sp.Id
        }
    }

# Export to CSV
$results | Export-Csv -Path $OutputPath -NoTypeInformation
