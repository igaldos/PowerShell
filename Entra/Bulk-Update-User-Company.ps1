# Import Microsoft Graph module if not already imported
Import-Module Microsoft.Graph.Users

# Connect to Microsoft Graph (interactive login)
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Load users from CSV
$csvPath = "C:\temp\users_to_update.csv"
$users = Import-Csv -Path $csvPath

# Initialize counters
$successCount = 0
$failCount = 0
$skipCount = 0

Write-Host "Starting user updates..." -ForegroundColor Cyan

foreach ($user in $users) {
    $upn = $user.userPrincipalName
    $targetCompany = $user.companyName

    try {
        # Get current user info
        $currentUser = Get-MgUser -UserId $upn -Property CompanyName

        if ($currentUser.CompanyName -eq $targetCompany) {
            Write-Host "SKIPPED: $upn already has company '$targetCompany'" -ForegroundColor Yellow
            $skipCount++
            continue
        }

        # Update company name
        Update-MgUser -UserId $upn -CompanyName $targetCompany -ErrorAction Stop
        Write-Host "SUCCESS: Updated $upn to company '$targetCompany'" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Host "FAILURE: Could not update $upn - $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
}

# Summary
Write-Host ""
Write-Host "Update complete." -ForegroundColor Cyan
Write-Host "Total successful updates: $successCount" -ForegroundColor Green
Write-Host "Total skipped: $skipCount" -ForegroundColor Yellow
Write-Host "Total failures: $failCount" -ForegroundColor Red