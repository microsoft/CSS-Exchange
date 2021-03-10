# Get-MRMDetails
This script will gather the MRM configuration for a given user. It will collect the current MRM Policy and Tags for the Exchange Organization, the current MRM Policy and Tags applied to the user, the current Exchange Diagnostics Logs for the user, and Exchange Audit logs for the mailbox selected.  The resulting data will allow you to see what tags are applied to the user and when the Managed Folder Assistant has run against the user. It also will grab the Admin Audit log so that we can tell if the Tags or Polices have been modified and who modified them.

The syntax for this script is as follows:

.\Get-MRMDetails.ps1 -Mailbox <user>

Example:

.\Get-MRMDetails.ps1 -Mailbox rob@contoso.com

 

 For Any issues or to get the latest version or contribute goto https://aka.ms/GetMRMDetails
