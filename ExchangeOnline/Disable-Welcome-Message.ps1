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

#Get All Groups where Welcome Email is enabled
#$WelcomeEmailGroups = Get-UnifiedGroup | Where-Object { $_.WelcomeMessageEnabled -eq $True }
 
#Disable Welcome Email
#ForEach($Group in $WelcomeEmailGroups) 
#{
    #Disable the Group Welcome Message Email
    #Set-UnifiedGroup -Identity $Group.Id -UnifiedGroupWelcomeMessageEnabled:$false
    #Write-host "Welcome Email Disabled for the Group:"$Group.PrimarySmtpAddress
#}