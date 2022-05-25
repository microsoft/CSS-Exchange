# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Syntax for running this script:
#
# .\Get-MRMDetails.ps1 -Mailbox <user>
#
# Example:
#
# .\Get-MRMDetails.ps1 -Mailbox rob@contoso.com
#

param (
    [Parameter(Mandatory = $true, HelpMessage = 'You must specify the name of a mailbox user')][string] $Mailbox
)

. $PSScriptRoot\ConvertPrStartTime.ps1
. $PSScriptRoot\Get-ManagedFolderProperties.ps1
. $PSScriptRoot\Get-RetentionProperties.ps1
. $PSScriptRoot\Get-AlternativeMailbox.ps1
#===================================================================
# MAIN
#===================================================================

if ($SDE -eq $True) {
    funcConvertPrStartTime
}

$MailboxProps = (Get-Mailbox $Mailbox)

if ($Null -ne $MailboxProps) {
    Write-Host -ForegroundColor "Green" "Found Mailbox $Mailbox, please wait while information is being gathered..."
}

else {
    Write-Host -ForegroundColor "Red" "The Mailbox $Mailbox cannot be found, please check spelling and try again!"
    exit
}

$File = "$Mailbox - MRM Summary.txt"

$Msg = "export complete, see file please send all files that start with $Mailbox - to your Microsoft Support Engineer"

if (($Null -eq $MailboxProps.RetentionPolicy) -and ($Null -eq $MailboxProps.ManagedFolderMailboxPolicy)) {
    Write-Host -ForegroundColor "Yellow" "The Mailbox does not have a Retention Policy or Managed Folder Policy applied!"
    exit
}

elseif ($Null -ne $MailboxProps.RetentionPolicy) {
    New-Item $File -Type file -Force | Out-Null
    funcRetentionProperties
    Write-Host -ForegroundColor "Green" $Msg
}

else {
    New-Item $File -Type file -Force | Out-Null
    funcManagedFolderProperties
    Write-Host -ForegroundColor "Green" $Msg
}
