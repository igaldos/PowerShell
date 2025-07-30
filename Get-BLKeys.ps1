<#
.SYNOPSIS
  Export BitLocker recovery key IDs for machines managed in Intune.

.DESCRIPTION
  - Reads a CSV file containing a single 'MachineName' column.
  - Connects to Microsoft Graph (Device.Read.All,BitlockerKey.Read.All).
  - Retrieves only Windows devices, excluding Cloud PC/Windows365.
  - Retrieves BitLocker recovery key IDs via Graph’s InformationProtection endpoint.
  - Exports the results to a CSV file.
  - Exports to log file (only IDs, no plaintext keys).

.PARAMETER MachinesCSV
  Path to the CSV file (signle column with header ‘MachineName’).

.PARAMETER OutputPath
  Path to save the output CSV file. Defaults to “.\DeviceRecoveryKeys.csv”.

.PARAMETER Verbose
  Switch to enable detailed logging to the console.

.NOTES
  Author:    Ignacio Galdos
  Date:      2025-07-30
  Version:   2.0
  Updates:   • Added progress bars for device lookup & key collection
             • Switched to exporting only recovery key IDs
             • Improved log readability

.EXAMPLE
  .\Get-BLKeysv2.ps1 -MachinesCsv '.\machines.csv' -Verbose
#>
Param (
    [string]$MachinesCSV
)

# Setup
$ScriptName = 'Get-BLKeys'

# Determine log and output paths
$LogDir = Split-Path -Parent $MachinesCSV
if (-not $LogDir) { $LogDir = (Get-Location).Path }
$LogFile = Join-Path $LogDir "$ScriptName.log"
$OutCsv  = Join-Path $LogDir 'DeviceRecoveryKeys.csv'

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Out-File -FilePath $LogFile -Append -InputObject $entry
}

Write-Log "Script start: $MachinesCSV"

# Validate CSV
Write-Progress -Activity 'Validation' -Status 'Checking CSV' -PercentComplete 0
if (-not (Test-Path $MachinesCSV) -or $MachinesCSV -notlike '*.csv') {
    Write-Log "Invalid CSV: $MachinesCSV" 'ERROR'
    Write-Progress -Activity 'Validation' -Completed
    exit 1
}
Write-Progress -Activity 'Validation' -Status 'Loading CSV' -PercentComplete 50
$csv = Import-Csv $MachinesCSV -ErrorAction Stop
if ($csv.Count -eq 0 -or -not $csv[0].PSObject.Properties.Name.Contains('MachineName')) {
    Write-Log "CSV missing 'MachineName' header or empty" 'ERROR'
    Write-Progress -Activity 'Validation' -Completed
    exit 1
}
Write-Progress -Activity 'Validation' -Completed
Write-Log 'CSV validated'

# Authenticate
Write-Progress -Activity 'Authentication' -Status 'Connecting to Graph' -PercentComplete 0
try {
    Connect-MgGraph -Scopes Device.Read.All,BitlockerKey.Read.All -NoWelcome -ErrorAction Stop
    Write-Progress -Activity 'Authentication' -Completed
    Write-Log 'Authentication successful'
} catch {
    Write-Log "Graph auth failed: $_" 'ERROR'
    Write-Progress -Activity 'Authentication' -Completed
    exit 1
}

# Lookup devices
$totalDevices = $csv.Count
$i = 0
Write-Progress -Activity 'Lookup Devices' -Status "0 of $totalDevices" -PercentComplete 0
$devices = foreach ($entry in $csv) {
    $i++
    $pct = [int](($i / $totalDevices) * 100)
    Write-Progress -Activity 'Lookup Devices' -Status "$i of $($totalDevices): $($entry.MachineName)" -PercentComplete $pct
    Get-MgDevice -Filter "displayName eq '$($entry.MachineName)'" -All -ErrorAction SilentlyContinue |
      Where-Object { $_.operatingSystem -like 'Windows*' -and $_.model -ne 'Cloud PC' -and $_.physicalIds -notcontains 'Windows365' }
}
Write-Progress -Activity 'Lookup Devices' -Completed

# Collect keys
$results = @()
$total = $devices.Count
$i = 0
Write-Progress -Activity 'Collect Keys' -Status "0 of $total" -PercentComplete 0
foreach ($d in $devices) {
    $i++
    $pct = [int](($i / $total) * 100)
    Write-Progress -Activity 'Collect Keys' -Status "$i of $($total): $($d.DisplayName)" -PercentComplete $pct

    $keys = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$($d.DeviceId)'" -All -ErrorAction SilentlyContinue
    Write-Log "${d.DisplayName}: $($keys.Count) key(s)"

    if ($keys.Count -eq 0) {
        $results += [PSCustomObject]@{
            DeviceName    = $d.DisplayName
            DeviceId      = $d.DeviceId
            RecoveryKeyId = 'NoKeyFound'
            RecoveryKey   = ''
        }
    } else {
        foreach ($k in $keys) {
            $results += [PSCustomObject]@{
                DeviceName    = $d.DisplayName
                DeviceId      = $d.DeviceId
                RecoveryKeyId = $k.Id
                RecoveryKey   = $k.key
            }
        }
    }
}
Write-Progress -Activity 'Collect Keys' -Completed

# Export results
Write-Progress -Activity 'Export' -Status "Saving $($results.Count) records" -PercentComplete 0
Write-Log "Exporting $($results.Count) records"
$results | Export-Csv $OutCsv -NoTypeInformation -Force
Write-Progress -Activity 'Export' -Completed
Write-Log 'Script complete'

Write-Output "✅ Recovery keys -> $(Resolve-Path $OutCsv)"
