# Create Temporary Access Pass for Microsoft Graph Users (Single or Bulk)
# This script creates temporary access passes for one or multiple users and exports results to HTML

<#
.SYNOPSIS
    Creates temporary access passes for Microsoft 365 users using Microsoft Graph API.

.DESCRIPTION
    This script automates the creation of temporary access passes (TAP) for Microsoft 365 users.
    It supports single user creation, bulk processing from arrays, or processing from CSV files.
    Results can be exported to a professional HTML report for documentation and sharing.

    Features:
    - Single user or bulk user processing (up to hundreds of users)
    - CSV file input with automatic column detection (UserId, UserPrincipalName, or upn)
    - Configurable TAP settings (lifetime, start time, single/multi-use)
    - Professional HTML reporting with success/failure tracking
    - Rate limiting protection with configurable delays
    - Comprehensive error handling and logging

.PARAMETER UserId
    Single user ID (email address) for creating one temporary access pass.
    Cannot be used with UserList or InputCsvFile parameters.

.PARAMETER UserList
    Array of user IDs (email addresses) for bulk processing.
    Cannot be used with UserId or InputCsvFile parameters.

.PARAMETER InputCsvFile
    Path to CSV file containing user information. 
    CSV must have a column named 'UserId', 'UserPrincipalName', or 'upn'.
    Cannot be used with UserId or UserList parameters.

.PARAMETER StartDateTime
    When the temporary access pass becomes active.
    Default: 2 minutes from current time to avoid "past time" API errors.

.PARAMETER LifetimeInMinutes
    How long the temporary access pass remains valid (in minutes).
    Default: 480 minutes (8 hours).
    Range: 10-43200 minutes (10 minutes to 30 days).

.PARAMETER IsUsableOnce
    Whether the pass can only be used once ($true) or multiple times ($false).
    Default: $false (reusable within the lifetime).

.PARAMETER Connect
    Automatically connect to Microsoft Graph if not already connected.
    Requires UserAuthenticationMethod.ReadWrite.All scope.

.PARAMETER ExportToHtml
    Path to export an HTML report with all temporary access pass details.
    Creates a professional report with summary statistics and individual results.

.PARAMETER DelayBetweenUsers
    Delay in seconds between processing each user to avoid API rate limits.
    Default: 1 second. Increase for large bulk operations.

.EXAMPLE
    .\Create-Temporary-Pass.ps1 -UserId "user@contoso.com" -Connect
    Creates a TAP for a single user with default settings (8 hours, reusable).

.EXAMPLE
    .\Create-Temporary-Pass.ps1 -UserId "user@contoso.com" -LifetimeInMinutes 1440 -IsUsableOnce $true -Connect
    Creates a 24-hour single-use TAP for one user.

.EXAMPLE
    $users = @("user1@contoso.com", "user2@contoso.com", "user3@contoso.com")
    .\Create-Temporary-Pass.ps1 -UserList $users -ExportToHtml "C:\Reports\BulkTAP.html"
    Creates TAPs for multiple users and exports results to HTML.

.EXAMPLE
    .\Create-Temporary-Pass.ps1 -InputCsvFile "C:\Users\employees.csv" -ExportToHtml "C:\Reports\EmployeeTAPs.html" -Connect -DelayBetweenUsers 2
    Bulk processes users from CSV file with 2-second delays and HTML export.

.INPUTS
    CSV file with columns: UserId, UserPrincipalName, or upn
    String array of user IDs
    Single user ID string

.OUTPUTS
    Console output with progress and results
    HTML report file (if ExportToHtml specified)
    PSCustomObject array with results (internal)

.NOTES
    Version: 2.0
    Author: PowerShell TAP Management Script
    Requires: Microsoft Graph PowerShell SDK
    Permissions: UserAuthenticationMethod.ReadWrite.All

    Prerequisites:
    1. Install Microsoft Graph PowerShell: Install-Module Microsoft.Graph
    2. Admin consent for UserAuthenticationMethod.ReadWrite.All scope
    3. Global Administrator or Authentication Administrator role

    CSV Format Example:
    upn
    user1@contoso.com
    user2@contoso.com
    user3@contoso.com

.LINK
    https://docs.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ParameterSetName = 'SingleUser')]
    [string]$UserId,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'BulkUsers')]
    [string[]]$UserList,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'FromFile')]
    [string]$InputCsvFile,
    
    [Parameter(Mandatory = $false)]
    [datetime]$StartDateTime = (Get-Date).AddMinutes(2),
    
    [Parameter(Mandatory = $false)]
    [int]$LifetimeInMinutes = 480,
    
    [Parameter(Mandatory = $false)]
    [bool]$IsUsableOnce = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$Connect,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportToHtml,
    
    [Parameter(Mandatory = $false)]
    [int]$DelayBetweenUsers = 1
)

# Function to connect to Microsoft Graph if needed
function Connect-ToMgGraph {
    try {
        Write-Host "Checking Microsoft Graph connection..." -ForegroundColor Yellow
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -NoWelcome
            Write-Host "Connected successfully!" -ForegroundColor Green
        } else {
            Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        return $false
    }
    return $true
}

# Function to create TAP for a single user
function New-SingleTAP {
    param(
        [string]$User,
        [datetime]$Start,
        [int]$Lifetime,
        [bool]$SingleUse
    )
    
    try {
        # Validate the user exists
        $userObj = Get-MgUser -UserId $User -ErrorAction Stop
        
        # Prepare the properties for the temporary access pass
        $properties = @{
            startDateTime = $Start.ToString("yyyy-MM-dd HH:mm:ss")
            lifetimeInMinutes = $Lifetime
            isUsableOnce = $SingleUse
        }

        # Convert to JSON
        $propertiesJSON = $properties | ConvertTo-Json -Depth 3

        # Create the temporary access pass
        $tapResult = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $User -BodyParameter $propertiesJSON

        return [PSCustomObject]@{
            Success = $true
            UserId = $User
            DisplayName = $userObj.DisplayName
            TemporaryAccessPass = $tapResult.TemporaryAccessPass
            CreatedDateTime = $tapResult.CreatedDateTime
            StartDateTime = $tapResult.StartDateTime
            LifetimeInMinutes = $tapResult.LifetimeInMinutes
            IsUsableOnce = $tapResult.IsUsableOnce
            State = $tapResult.State
            Error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            UserId = $User
            DisplayName = "Unknown"
            TemporaryAccessPass = $null
            CreatedDateTime = $null
            StartDateTime = $null
            LifetimeInMinutes = $null
            IsUsableOnce = $null
            State = $null
            Error = $_.Exception.Message
        }
    }
}

# Function to generate bulk HTML report
function New-BulkHtmlReport {
    param(
        [array]$Results,
        [string]$FilePath
    )
    
    $successCount = ($Results | Where-Object { $_.Success }).Count
    $failureCount = ($Results | Where-Object { -not $_.Success }).Count
    $createdBy = (Get-MgContext).Account
    $exportTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $totalCount = $Results.Count
    
    # Build HTML header
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Bulk Temporary Access Pass Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .summary { background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .success-row { background-color: #f8fff8; }
        .error-row { background-color: #fff8f8; }
        .tap-code { background-color: #000; color: #ffff00; padding: 8px; border-radius: 3px; font-family: monospace; font-size: 14px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; word-wrap: break-word; }
        th { background-color: #4CAF50; color: white; position: sticky; top: 0; }
        tr:hover { background-color: #f0f0f0; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 5px; margin: 15px 0; }
        .timestamp { color: #666; font-size: 0.9em; text-align: center; margin-top: 20px; }
        .error-text { color: #d32f2f; font-style: italic; }
        .stats { display: flex; justify-content: space-around; margin: 15px 0; }
        .stat { text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .success-stat { color: #4CAF50; }
        .error-stat { color: #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Bulk Temporary Access Pass Report</h1>
        
        <div class="summary">
            <h3>Summary</h3>
            <div class="stats">
                <div class="stat">
                    <div class="stat-number success-stat">$successCount</div>
                    <div>Successful</div>
                </div>
                <div class="stat">
                    <div class="stat-number error-stat">$failureCount</div>
                    <div>Failed</div>
                </div>
                <div class="stat">
                    <div class="stat-number">$totalCount</div>
                    <div>Total</div>
                </div>
            </div>
            <strong>Created By:</strong> $createdBy<br>
            <strong>Generated:</strong> $exportTime
        </div>

        <div class="warning">
            <strong>IMPORTANT:</strong> Save all temporary access passes immediately as they cannot be retrieved again!
        </div>

        <table>
            <tr>
                <th>Status</th>
                <th>User</th>
                <th>Display Name</th>
                <th>Temporary Access Pass</th>
                <th>Start Time</th>
                <th>Lifetime</th>
                <th>Single Use</th>
                <th>Error</th>
            </tr>
"@

    # Build table rows
    $htmlRows = ""
    foreach ($result in $Results) {
        $rowClass = if ($result.Success) { "success-row" } else { "error-row" }
        $statusIcon = if ($result.Success) { "SUCCESS" } else { "FAILED" }
        $tapDisplay = if ($result.Success) { "<div class='tap-code'>$($result.TemporaryAccessPass)</div>" } else { "N/A" }
        $errorDisplay = if (-not $result.Success) { "<span class='error-text'>$($result.Error -replace '"', '&quot;')</span>" } else { "" }
        
        $htmlRows += @"
            <tr class="$rowClass">
                <td>$statusIcon</td>
                <td>$($result.UserId)</td>
                <td>$($result.DisplayName)</td>
                <td>$tapDisplay</td>
                <td>$($result.StartDateTime)</td>
                <td>$($result.LifetimeInMinutes) min</td>
                <td>$($result.IsUsableOnce)</td>
                <td>$errorDisplay</td>
            </tr>
"@
    }

    # Build HTML footer
    $htmlFooter = @"
        </table>
        
        <div class="timestamp">
            Report generated on: $exportTime
        </div>
    </div>
</body>
</html>
"@

    # Combine all parts
    $htmlContent = $htmlHeader + $htmlRows + $htmlFooter
    
    $htmlContent | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main script execution
Write-Host "=== Bulk Temporary Access Pass Creation Script ===" -ForegroundColor Cyan
Write-Host ""

# Connect to Microsoft Graph if requested or if not already connected
if ($Connect -or -not (Get-MgContext -ErrorAction SilentlyContinue)) {
    if (-not (Connect-ToMgGraph)) {
        exit 1
    }
}

# Determine the list of users to process
$usersToProcess = @()

if ($UserId) {
    $usersToProcess = @($UserId)
    Write-Host "Processing single user: $UserId" -ForegroundColor Yellow
}
elseif ($UserList) {
    $usersToProcess = $UserList
    Write-Host "Processing $($UserList.Count) users from parameter list" -ForegroundColor Yellow
}
elseif ($InputCsvFile) {
    if (Test-Path $InputCsvFile) {
        $csvData = Import-Csv $InputCsvFile
        if ($csvData[0].PSObject.Properties.Name -contains 'UserId') {
            $usersToProcess = $csvData.UserId
        } elseif ($csvData[0].PSObject.Properties.Name -contains 'UserPrincipalName') {
            $usersToProcess = $csvData.UserPrincipalName
        } elseif ($csvData[0].PSObject.Properties.Name -contains 'upn') {
            $usersToProcess = $csvData.upn
        } else {
            Write-Error "CSV file must contain either 'UserId', 'UserPrincipalName', or 'upn' column"
            exit 1
        }
        Write-Host "Processing $($usersToProcess.Count) users from CSV file: $InputCsvFile" -ForegroundColor Yellow
    } else {
        Write-Error "CSV file not found: $InputCsvFile"
        exit 1
    }
}
else {
    Write-Error "You must specify either -UserId, -UserList, or -InputCsvFile"
    exit 1
}

Write-Host ""
Write-Host "TAP Settings:" -ForegroundColor Cyan
Write-Host "  Start Time: $StartDateTime" -ForegroundColor White
Write-Host "  Lifetime: $LifetimeInMinutes minutes" -ForegroundColor White
Write-Host "  Single Use: $IsUsableOnce" -ForegroundColor White
Write-Host "  Delay Between Users: $DelayBetweenUsers seconds" -ForegroundColor White
Write-Host ""

# Process each user
$results = @()
$currentUser = 1

foreach ($user in $usersToProcess) {
    Write-Host "[$currentUser/$($usersToProcess.Count)] Processing: $user" -ForegroundColor Yellow
    
    $result = New-SingleTAP -User $user -Start $StartDateTime -Lifetime $LifetimeInMinutes -SingleUse $IsUsableOnce
    $results += $result
    
    if ($result.Success) {
        Write-Host "  Success - TAP: $($result.TemporaryAccessPass)" -ForegroundColor Green
    } else {
        Write-Host "  Failed - $($result.Error)" -ForegroundColor Red
    }
    
    $currentUser++
    
    # Add delay between users to avoid rate limiting
    if ($currentUser -le $usersToProcess.Count -and $DelayBetweenUsers -gt 0) {
        Start-Sleep -Seconds $DelayBetweenUsers
    }
}

# Display summary
$successCount = ($results | Where-Object { $_.Success }).Count
$failureCount = ($results | Where-Object { -not $_.Success }).Count

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failureCount" -ForegroundColor Red
Write-Host "Total: $($results.Count)" -ForegroundColor White
Write-Host ""

# Export to HTML if requested
if ($ExportToHtml) {
    try {
        New-BulkHtmlReport -Results $results -FilePath $ExportToHtml
        Write-Host "Bulk report exported to: $ExportToHtml" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export HTML report: $($_.Exception.Message)"
    }
}

# Show failed users if any
$failedUsers = $results | Where-Object { -not $_.Success }
if ($failedUsers) {
    Write-Host ""
    Write-Host "Failed Users:" -ForegroundColor Red
    foreach ($failed in $failedUsers) {
        Write-Host "  $($failed.UserId): $($failed.Error)" -ForegroundColor Red
    }
}
