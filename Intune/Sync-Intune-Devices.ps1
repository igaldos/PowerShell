# SYNOPSIS
# Sends a sync request to all Windows devices managed by Intune in the specified tenant using Microsoft Graph PowerShell SDK.
# AUTHOR
# Ignacio Galdos
#
# USAGE
# Update the -TenantId parameter with your Azure AD tenant ID.
# Run this script in a PowerShell session with the necessary permissions.


# Prerequisite: Install the Graph SDK if not already installed
# Install-Module Microsoft.Graph -Scope CurrentUser

# Example usage:
# .\Sync-Intune-Devices.ps1 -TenantId 1a234b56-cfea-4ef9-89ab-1b94de027731

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Enter your Azure AD Tenant ID or domain name")]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false, HelpMessage="Filter devices by operating system")]
    [string]$OperatingSystem = "Windows"
)


# Import only the DeviceManagement service (Intune) cmdlets if not already imported
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
    Write-Error 'Microsoft.Graph.DeviceManagement module is not installed. Please run: Install-Module Microsoft.Graph -Scope CurrentUser'
    return
}
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop


# Switch to the beta endpoint profile (if you need beta‑only APIs)
# Select-MgProfile -Name beta


# Connect with just the consent you need
Connect-MgGraph -TenantId $TenantId -Scopes DeviceManagementManagedDevices.ReadWrite.All,DeviceManagementManagedDevices.PrivilegedOperations.All


# Retrieve all devices matching the specified OS (paging through if necessary)
$allDevices = Get-MgDeviceManagementManagedDevice -All |
    Where-Object { $_.OperatingSystem -eq $OperatingSystem }


foreach ($device in $allDevices) {
    try {
        Sync-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id
        Write-Host "Sent sync request to $($device.DeviceName)" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to sync $($device.DeviceName): $($PSItem.Exception.Message)"
    }
}
