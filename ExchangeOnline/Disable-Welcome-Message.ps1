# Connect to Exchange Online if not already connected
Connect-ExchangeOnline

# Import CSV with Identity column
$groups = Import-Csv -Path "C:\temp\entra_groups.csv"

foreach ($group in $groups) {
    try {
        Write-Host "Disabling welcome message for group: $($group.Identity)"
        Set-UnifiedGroup -Identity $group.Identity -UnifiedGroupWelcomeMessageEnabled:$false -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to update group '$($group.Identity)': $_"
    }
}