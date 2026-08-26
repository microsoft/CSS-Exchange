# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# Import-MailPublicFolders.ps1
# Create dummy mail public folder objects in target forest
#
# The script needs to be run from Onprem.
#
# One of the forest involved should always be cloud.
#
# If the input do not contain the switch parameter, then the target forest will be assumed as Onprem.
#
# Default URI to connect to cloud is https://outlook.office365.com/powerShell-liveID. This can be changed by passing the appropriate URI to ConnectionUri parameter
#
# Example input to the script:
#
# Import-MailPublicFolders.ps1 -ToCloud

[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory=$false)]
    [PSCredential] $Credential,

    [Parameter(Mandatory=$false)]
    [Switch] $ToCloud,

    [Parameter(Mandatory=$false)]
    [string] $ConnectionUri = "https://outlook.office365.com/powerShell-liveID",

    [Parameter(Mandatory=$true, ParameterSetName="ScriptUpdateOnly")]
    [switch] $ScriptUpdateOnly,

    [Parameter(Mandatory=$false)]
    [switch] $SkipVersionCheck
)

. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

# Create a tenant PSSession against Exchange Online with modern auth.
function CreateTenantSession() {
    param (
        [string] $ConnUri,
        [PSCredential] $Credential
    )

    Import-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
    if (Get-Module -Name ExchangeOnlineManagement) {
        $connectParams = @{
            ConnectionUri = $ConnUri
            Prefix        = "Remote"
            ErrorAction   = "SilentlyContinue"
        }

        if ($null -ne $Credential) {
            $connectParams.Credential = $Credential
        }
        Connect-ExchangeOnline @connectParams
    } else {
        Write-Warning "This script uses modern authentication to connect to Exchange Online and requires EXO V2 module to be installed. Please follow the instructions at https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module to install EXO V2 module."
        exit
    }
}

## Get organization guid
function GetOrganizationGuid() {
    param ($targetForest)

    $organizationGuid = ""
    if ($targetForest) {
        $orgConfig = Get-OrganizationConfig -ErrorAction:SilentlyContinue
    } else {
        $orgConfig = Get-RemoteOrganizationConfig -ErrorAction:SilentlyContinue
    }

    # Return the results
    if ($null -ne $orgConfig) {
        $organizationGuid = $($orgConfig.Guid.ToString())
    }

    return $organizationGuid
}

## Retrieve mail public folders
function GetMailPublicFolders() {
    param ($fromSource, $targetForest)

    $mailPublicFolders = @()
    if (($fromSource -and $targetForest) -or (!$fromSource -and !$targetForest)) {
        $mailPublicFolders = Get-MailPublicFolder -ResultSize:Unlimited -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    } else {
        $mailPublicFolders = Get-RemoteMailPublicFolder -ResultSize:Unlimited -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    }

    return $mailPublicFolders
}

## MailPublicFolders whose external email address do not point to an
## existing object need to be removed
function RemoveOrphanMailPublicFolders() {
    param ($srcFolderHashtable, $tgtMailPublicFolders, $targetForest, $orgGuid)

    foreach ($mailPublicFolder in $tgtMailPublicFolders) {
        if ($null -ne $mailPublicFolder.ExternalEmailAddress) {
            if ($srcFolderHashtable.ContainsKey($mailPublicFolder.ExternalEmailAddress.ToString())) {
                $srcFolderHashtable.Remove($mailPublicFolder.ExternalEmailAddress.ToString())
                continue
            } elseif ($srcFolderHashtable.ContainsKey($mailPublicFolder.ExternalEmailAddress.ToString().ToUpper().Replace("SMTP:", ""))) {
                $srcFolderHashtable.Remove($mailPublicFolder.ExternalEmailAddress.ToString().ToUpper().Replace("SMTP:", ""))
                continue
            }
        }

        if ($null -ne $mailPublicFolder.LegacyExchangeDN -and ($mailPublicFolder.LegacyExchangeDN.Contains($orgGuid))) {
            if ($targetForest) {
                Disable-RemoteMailPublicFolder -Identity $mailPublicFolder.Alias -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue -Confirm:$false
            } else {
                Disable-MailPublicFolder -Identity $mailPublicFolder.Alias -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue -Confirm:$false
            }
        }
    }

    return $srcFolderHashtable
}

## Retrieve accepted domains
function GetAcceptedDomains() {
    param ($targetForest)

    $acceptedDomains = @()
    if ($targetForest) {
        $acceptedDomains = Get-RemoteAcceptedDomain -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    } else {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
    }

    return $acceptedDomains
}

## Import mail public folders.
function ImportMailPublicFolders() {
    param ($targetForest, $acceptedDomains, $srcFolderHashtable, $orgGuid)

    if ($targetForest) {
        $cmdletToExecute = "New-RemoteSyncMailPublicFolder"
    } else {
        $cmdletToExecute = "New-SyncMailPublicFolder"
    }

    $acceptedDomainCount = $acceptedDomains.Count
    $inputParameters = @{}
    foreach ($mailPublicFolder in $($srcFolderHashtable.Values)) {
        # Collect the properties of mail enabled public folder
        $alias = $mailPublicFolder.Alias.Trim()
        $name = $mailPublicFolder.Name.Trim()
        $entryId = $mailPublicFolder.EntryId.ToString()
        $windowsEmailAddress = $mailPublicFolder.WindowsEmailAddress.ToString()
        $externalEmailAddress = $mailPublicFolder.PrimarySmtpAddress.ToString()

        if ($alias.Length -lt 1 -or
            $entryId.Length -lt 1 -or
            $externalEmailAddress.Length -lt 1) {
            continue
        }

        $entryId = $orgGuid + $entryId

        $emailAddressesArray = @($mailPublicFolder.EmailAddresses)

        if ($windowsEmailAddress -ne "") {
            $localPart = @($windowsEmailAddress.Split('@'))[0]
            for ($index = 0; $index -lt $acceptedDomainCount; $index++) {
                $emailAddressesArray += $localPart + "@" + $acceptedDomains[$index].DomainName.ToString()
            }
        }

        for ($index = 0; $index -lt $emailAddressesArray.Count; $index++) {
            $emailAddressesArray[$index] = $emailAddressesArray[$index].ToString().Replace("SMTP:", "")
            $emailAddressesArray[$index] = $emailAddressesArray[$index].ToString().Replace("smtp:", "")
        }

        # Remove duplicate email addresses if any
        $emailAddressesArray = $emailAddressesArray | Sort-Object -Unique

        $inputParameters.Clear()
        $inputParameters.Add("Name", $name)
        $inputParameters.Add("Alias", $alias)

        if ($($mailPublicFolder.HiddenFromAddressListsEnabled) -eq "True") {
            $inputParameters.Add("HiddenFromAddressListsEnabled", $true)
        }

        $inputParameters.Add("EmailAddresses", $emailAddressesArray)
        $inputParameters.Add("EntryId", $entryId)

        if ($windowsEmailAddress -ne "") {
            $inputParameters.Add("WindowsEmailAddress", $windowsEmailAddress)
        }

        if ($externalEmailAddress -ne "") {
            $inputParameters.Add("ExternalEmailAddress", $externalEmailAddress)
        }

        $inputParameters.Add("ErrorAction", "Continue")
        $inputParameters.Add("WarningAction", "Continue")

        # Execute the command
        &$cmdletToExecute @inputParameters
    }
}

################################ BEGINNING OF SCRIPT ################################

# Create a PSSession for this organization
CreateTenantSession -ConnUri $ConnectionUri -Credential $Credential

# Determine the guid of the organization from where to export objects
$organizationGuid = GetOrganizationGuid -targetForest $ToCloud

# Get mail enabled public folders from source forest
$sourceMailPublicFolders = @(GetMailPublicFolders -fromSource $true -targetForest $ToCloud)

$sourceFoldersHashTable = @{}
foreach ($mailPublicFolder in $sourceMailPublicFolders) {
    $sourceFoldersHashTable.Add($mailPublicFolder.PrimarySmtpAddress.ToString(), $mailPublicFolder)
}

# Get mail enabled public folders from target forest
$targetMailPublicFolders = @(GetMailPublicFolders -fromSource $false -targetForest $ToCloud)

if ($targetMailPublicFolders.Count -gt 0) {
    $sourceFoldersHashTable = RemoveOrphanMailPublicFolders -srcFolderHashtable $sourceFoldersHashTable -tgtMailPublicFolders $targetMailPublicFolders -targetForest $ToCloud -orgGuid $organizationGuid
}

Write-Host "Successfully removed any existing orphan mail public folders already created by the script"

if ($sourceMailPublicFolders.Count -lt 1) {
    if ($ToCloud) {
        Write-Host "Couldn't find any mail enabled public folder objects in Onprem environment"
    } else {
        Write-Host "Couldn't find any mail enabled public folder objects in Cloud environment"
    }

    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    exit
}

# Retrieve the accepted domains for this organization
$acceptedDomains = @(GetAcceptedDomains -targetForest $ToCloud)

# Import the mail enabled public folders to other forest
ImportMailPublicFolders -targetForest $ToCloud -acceptedDomains $acceptedDomains -srcFolderHashtable $sourceFoldersHashTable -orgGuid $organizationGuid

Write-Host "Completed importing of mail enabled public folders"

# Terminate the PSSession
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
################################ END OF SCRIPT ################################
