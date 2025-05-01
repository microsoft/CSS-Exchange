# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# Import-PublicFolderMailboxes.ps1
#    Import the public folder mailboxes as mail enabled users from cloud to on-premise
#
# Example input to the script:
#
# Import-PublicFolderMailboxes.ps1 -ConnectionUri <cloud url>
#
# The above example imports public folder mailbox objects from cloud as mail enabled users to on-premise.
param (
    [Parameter(Mandatory = $false)]
    [PSCredential] $Credential,

    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [string] $ConnectionUri = "https://outlook.office365.com/powerShell-liveID"
)

#cspell:words EXOV2

## Create a tenant PSSession.
function CreateTenantSession() {
    Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
    if (Get-Module ExchangeOnlineManagement) {
        $sessionOption = (New-PSSessionOption -SkipCACheck)
        Connect-ExchangeOnline -Credential $Credential -ConnectionUri $ConnectionUri -PSSessionOption $sessionOption -Prefix "Remote" -ErrorAction SilentlyContinue
    } else {
        Write-Warning $LocalizedStrings.EXOV2ModuleNotInstalled
        exit
    }
}

## Writes a dated information message to console
function WriteInfoMessage() {
    param ($message)
    Write-Host "[$($(Get-Date).ToString())]" $message
}

## Retrieve public folder mailboxes
function GetPublicFolderMailBoxes() {
    $publicFolderMailboxes = Get-RemoteMailbox -PublicFolder -ResultSize:Unlimited -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    $publicFolderMailboxes = $publicFolderMailboxes | Where-Object { -not $_.IsExcludedFromServingHierarchy } | Select-Object -First 10

    # Return the results
    if ($null -eq $publicFolderMailboxes -or ([array]($publicFolderMailboxes)).Count -lt 1) {
        return $null
    }

    return $publicFolderMailboxes
}

## Sync public folder mailboxes from cloud to on-prem.
function SyncPublicFolderMailboxes(
    [object[]] $publicFolderMailboxes) {
    WriteInfoMessage ($LocalizedStrings.DeletingMailUsersInfo)
    $remoteMailboxes = Get-OrganizationConfig | Select-Object RemotePublicFolderMailboxes

    foreach ($adObjectId in $remoteMailboxes.RemotePublicFolderMailboxes) {
        $mailUser = Get-MailUser $adObjectId -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

        if ($null -ne $mailUser) {
            WriteInfoMessage ($LocalizedStrings.RemovingMailUsers -f $mailUser)
            Set-OrganizationConfig -RemotePublicFolderMailboxes @{Remove = $mailUser }

            WriteInfoMessage ($LocalizedStrings.DeleteMailUser -f $mailUser)
            Remove-MailUser $mailUser -Confirm:$false
        }
    }
    Set-OrganizationConfig -RemotePublicFolderMailboxes:$Null

    $validExternalEmailAddresses = @()
    $mailUserList = @()
    $domainController = $null

    if ($null -ne $publicFolderMailboxes) {
        $hasPublicFolderServingHierarchy = $false
        foreach ($publicFolderMailbox in $publicFolderMailboxes) {
            if ($publicFolderMailbox.IsExcludedFromServingHierarchy -eq $false) {
                $hasPublicFolderServingHierarchy = $true
                $displayName = $publicFolderMailbox.Name.ToString().Trim()
                $name = "RemotePfMbx-" + $displayName + "-" + [guid]::NewGuid()
                $name = $(if ($name.length -gt 64) { $name.substring(0, 64) } else { $name })
                $externalEmailAddress = $publicFolderMailbox.PrimarySmtpAddress.ToString()

                WriteInfoMessage ($LocalizedStrings.SyncingPublicFolderMailbox -f $displayName)

                $mailUser = Get-MailUser $externalEmailAddress -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

                if ($null -eq $mailUser) {
                    WriteInfoMessage ($LocalizedStrings.CreatingMailUser -f $displayName)
                    try {
                        $p = @{
                            Name                 = $name
                            ExternalEmailAddress = $externalEmailAddress
                            DisplayName          = $displayName
                        }

                        if ($null -ne $domainController) {
                            $p.DomainController = $domainController
                        }

                        $mailUser = New-MailUser @p
                        if ($null -eq $domainController -and $null -ne $mailUser) {
                            $domainController = $mailUser.OriginatingServer
                        }

                        $mailUserList += $mailUser
                    } catch {
                        Write-Host $error[0]
                    }
                } else {
                    WriteInfoMessage ($LocalizedStrings.MailUserExists -f $mailUser)
                }

                WriteInfoMessage ($LocalizedStrings.ConfiguringMailUser -f $mailUser)

                WriteInfoMessage ($LocalizedStrings.DoneSyncingPublicFolderMailbox -f $displayName)
                Write-Host ""
            }
        }
    }

    if (-not $hasPublicFolderServingHierarchy) {
        WriteInfoMessage ($LocalizedStrings.NoHierarchyPublicFolderMailbox)
        Write-Host ""
    }

    foreach ($mailUser in $mailUserList) {
        $validExternalEmailAddresses += $mailUser.ExternalEmailAddress
        Set-OrganizationConfig -RemotePublicFolderMailboxes @{Add = $mailUser } -DomainController $domainController
    }
}

#load hashtable of localized string
$LocalizedStrings = ConvertFrom-StringData @'
SyncingPublicFolderMailbox = Syncing public folder mailbox '{0}'.
CreatingMailUser = Creating MailUser object '{0}'.
MailUserExists = MailUser object '{0}' already exists for this public folder mailbox.
ConfiguringMailUser = Adding '{0}' to RemotePublicFolderMailboxes.
DoneSyncingPublicFolderMailbox = Done syncing public folder mailbox '{0}'
NoHierarchyPublicFolderMailbox = There aren't any public folder mailboxes, serving hierarchy, to import.
DeletingMailUsersInfo = Deleting MailUsers, if any, that don't have corresponding public folder mailboxes in the cloud, serving hierarchy.
RemovingMailUsers = Removing '{0}' from RemotePublicFolderMailboxes.
DeleteMailUser = Deleting MailUser object '{0}'.
IncorrectCredentials = Please provide correct credentials to establish remote session.
StartedPublicFolderMailboxImport = Started import of public folder mailboxes.
CompletedPublicFolderMailboxImport = Completed import of public folder mailboxes.
EXOV2ModuleNotInstalled = This script uses modern authentication to connect to Exchange Online and requires EXO V2 module to be installed. Please follow the instructions at https://docs.microsoft.com/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module to install EXO V2 module.
'@

# Create a tenant PSSession against Exchange Online with modern auth.
CreateTenantSession

WriteInfoMessage ($LocalizedStrings.StartedPublicFolderMailboxImport)
Write-Host ""

# Get mail enabled public folders in the organization
$publicFolderMailboxes = GetPublicFolderMailBoxes

# Create mail enabled users for remote public folder mailboxes
SyncPublicFolderMailboxes $publicFolderMailboxes

Write-Host ""
WriteInfoMessage ($LocalizedStrings.CompletedPublicFolderMailboxImport)

# Terminate the PSSession
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
