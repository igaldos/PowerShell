#Parameters
$MailboxID = "Mailbox Name" #Alias
$UserID = "user@contoso.com"
 
#Connect to Exchange Online
Connect-ExchangeOnline
 
#Grant Permission to the Shared Mailbox
Add-MailboxPermission -Identity $MailboxID -User $UserID -AccessRights FullAccess -InheritanceType All