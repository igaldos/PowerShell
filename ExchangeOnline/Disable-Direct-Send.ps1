Install-Module -Name ExchangeOnlineManagement -Force

Connect-ExchangeOnline

Set-OrganizationConfig -RejectDirectSend $true

#Verify
Get-OrganizationConfig | Select-Object Identity, RejectDirectSend

#Testing#

# $EmailMessage = @{
    #To         = "example@example.com"
    #From       = "example@example.com"
    #Subject    = "Test email"
    #Body       = "Test email for Direct Send"
    #SmtpServer = "example-com.mail.protection.outlook.com"
    #Port       = "25"#    UseSSL     = $true
# }

#Send-MailMessage @EmailMessage