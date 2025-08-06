# SYNOPSIS
# Sends a sync request to all Windows devices managed by Intune in the specified tenant using Microsoft Graph PowerShell SDK.
# AUTHOR
# Ignacio Galdos
#
# USAGE
# Update the -TenantId parameter with your Azure AD tenant ID.
# Run this script in a PowerShell session with the necessary permissions.

# Install the Graph SDK (v1.0 endpoints)
Install-Module Microsoft.Graph -AllowClobber -Force

# Option A: Import everything
# Import-Module Microsoft.Graph
# Option B: Import only the DeviceManagement service (Intune) cmdlets
Import-Module Microsoft.Graph.DeviceManagement

# Switch to the beta endpoint profile (if you need beta‑only APIs)
Select-MgProfile -Name beta

# Connect with just the consent you need
Connect-MgGraph -TenantId '' -Scopes DeviceManagementManagedDevices.ReadWrite.All,DeviceManagementManagedDevices.PrivilegedOperations.All

# Retrieve all Windows devices (paging through if necessary)
$allDevices = Get-MgDeviceManagementManagedDevice -All |
    Where-Object { $_.OperatingSystem -eq 'Windows' }

foreach ($device in $allDevices) {
    try {
        Sync-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id
        Write-Host "Sent sync request to $($device.DeviceName)" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to sync $($device.DeviceName): $_"
    }
}
