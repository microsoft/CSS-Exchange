# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# UnlockAndRestorePublicFolderProperties.ps1
#    It recovers the public folders with the Permissions it had before the lockdown process,
#    if the user want to fallback to public folders. However, any new content posted to group
#    will not be available in public folder.
#
# .DESCRIPTION
#    Script performs the following actions
#      1. It resumes PublicFolderClientPermissions of migrated public folders from backup file.
#      2. Mail-Enable and resume mail properties of any mail public folder which had migrated.
#      3. Resume the smtp addresses of mail public folders from the Proxy Address list of Groups.
#
#   After the execution of the script
#      1. All public folders which got migrated will resume it's permissions it had, at the
#         time of locking public folder
#      2. All mails sent to smtp addresses of mail public folder had, will be routed to the
#         mail public folders itself (No longer be redirected to group).
#      3. Any new item(s) posted to the group can only be accessed only from the group; after
#         restore process, public folder will not contain any new data that was posted in group.
#
# .PARAMETER Credential
#    Exchange Online user name and password. Don't use this param if MFA is enabled.
#
# .PARAMETER BackupDir
#    The directory that user had saved the permissions and other properties at the
#    time of locking public folders.
#
# .PARAMETER ArePublicFoldersOnPremises
#    Tells if public folders are on-premises. Set to '$true' if public folders are remote, else set to '$false'
#
# .PARAMETER ConnectionUri
#    The Exchange Online remote PowerShell connection uri. If you are an Office 365 operated by 21Vianet customer in China, use "https://partner.outlook.cn/PowerShell".
#
# .PARAMETER WhatIf
#    The WhatIf switch instructs the script to simulate the actions that it would take on the object. By using the WhatIf switch, you can view what changes would occur
#    without having to apply any of those changes. You don't have to specify a value with the WhatIf switch.
#
# .PARAMETER ScriptUpdateOnly
#    Only updates the script to the latest released version without performing any other actions.
#
# .PARAMETER SkipVersionCheck
#    Skips the automatic version check and script update.
#
# .EXAMPLE
#    .\UnlockAndRestorePublicFolderProperties.ps1 -BackupDir C:\PFToGroupMigration\ -WhatIf
#    .\UnlockAndRestorePublicFolderProperties.ps1 -BackupDir C:\PFToGroupMigration -ArePublicFoldersOnPremises $true

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [PSCredential] $Credential,

    [Parameter(Mandatory=$true, ParameterSetName="Default")]
    [ValidateNotNullOrEmpty()]
    [string] $BackupDir,

    [Parameter(Mandatory = $false, ParameterSetName="Default", HelpMessage = "Enter '`$true' if public folders are on-premises)")]
    [ValidateNotNullOrEmpty()]
    [bool] $ArePublicFoldersOnPremises = $false,

    [Parameter(Mandatory=$false, ParameterSetName="Default", HelpMessage = "Enter the Exchange Online remote PowerShell connection uri")]
    [ValidateNotNullOrEmpty()]
    [string] $ConnectionUri = "https://outlook.office365.com/powerShell-liveID",

    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [switch] $WhatIf = $false,

    [Parameter(Mandatory=$true, ParameterSetName="ScriptUpdateOnly")]
    [switch] $ScriptUpdateOnly,

    [Parameter(Mandatory=$false)]
    [switch] $SkipVersionCheck
)

. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

###################### START OF DEFAULTS ######################

if ($WhatIf) {
    $prefix = "test_"
} else {
    $prefix = $null
}

$permissionListCsv  = Join-Path $BackupDir ($prefix + "PfPermissions.csv")
$pfToGrpMappingCsv  = Join-Path $BackupDir ($prefix + "PfToGroupMapping.csv")
$pfMailPropCsv      = Join-Path $BackupDir ($prefix + "PfMailProperties.csv")
$logPath            = Join-Path $BackupDir ($prefix + "PfLockdown_summary.log")

$LocalizedStrings = ConvertFrom-StringData @'
WhatIfEnabled = IMPORTANT!!! WhatIf parameter is set, therefore no changes will be made. The messages shown are just a preview of the actual execution. All backup files are expected with a 'test_' prefix. If actual lockdown is performed, please create a copy of the backup files with prefix 'test_' to see the preview of this script.
UnsuccessfulGetRecipientPermissionCmdlet = Get-RecipientPermission cmdlet could not be executed. Please make sure the user is a member of role groups 'Organization Management' and 'Recipient Management' and try again.
BackupNotFound = Following backup files for recovery does not exists: {0}. Please move the files to backup directory and re-run the script.
ReadingPfPerms = Reading public folder permissions..
IncorrectCsv = Incorrect csv {0} provided.
ImportingBackupFilesSuccessful = Successfully imported {0} and {1}.
RestoringPfPerms = Restoring public folder permissions from backup file ({0}) ..
CredentialNotFound = Exchange Online credential not found. Please provide Exchange Online admin credential for the remote PowerShell login.
CreatingRemoteSession = Creating an Exchange Online remote PowerShell session...
FailedToCreateRemoteSession = Unable to create a remote PowerShell session to Exchange Online. The error is as follows: '{0}'.
FailedToImportRemoteSession = Exchange Online remote PowerShell session could not be imported. The error is as follows: '{0}'.
RemoteSessionCreatedSuccessfully = Exchange Online remote PowerShell session created successfully.
SkippingUser = Skipping permissions of user {0} as user is not found. Get-Recipient failed with this user value obtained from backup file.
RemovingPfPermission = Removing permission of user {0} on public folder {1}.
AddPfPermission = Adding permissions '{1}' to user {0} on public folder {2}.
RestoredPfPerms = Successfully restored all public folder permissions from backup file.
MailEnablingPfs = Mail enabling all migrating public folders..
MailEnabledAndRestoredProperties = Mail enabled {0} and restored mail properties.
RemovedPropertiesFromGroup = The following properties are removed from group '{0}': SendAs permissions of users {1}, SendOnBehalfTo permissions of users {2}, SMTP addresses {3}.
MailEnabledPf = Public folder {0} is mail enabled.
RemovingSendAsFromGroupFailed = Removing SendAs permission from group {0} failed..
SendAsPermissionRemovedFromGroup = SendAs permission of {0} have been removed from group {1}.
RestoringSMTPFailed = Restoring SMTP address of public folder {0} failed..
RestoringSMTPSucceeded = Successfully Restored SMTP address of public folder {0}.
AddingSendOnBehalfToPermissionFailed = Adding SendOnBehalfTo permission of user '{1}' to public folder '{0}' is failed.
AddingSendAsToPfFailed = Adding SendAs permission to public folder {0} failed..
AddedPropertiesBackToPf = The following properties are added back to public folder '{0}': SendAs permissions of users {1}, SendOnBehalfTo permissions of users {2}, emailAddressPolicyEnabled {3}.
PfRecoveryComplete = Public folders successfully restored.
EXOV2ModuleNotInstalled = This script uses modern authentication to connect to Exchange Online and requires EXO V2 module to be installed. Please follow the instructions at https://docs.microsoft.com/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module to install EXO V2 module.
'@

###################### END OF DEFAULTS ######################

# Function for logging events.
function WriteLog {
    [CmdletBinding()]
    param
    (
        # Log message
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        # Log file location
        [Parameter(Mandatory=$false)]
        [string]$Path="C:\Logs\",

        # Level of message
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]$Level="Info",

        # If log only
        [Parameter(Mandatory=$false)]
        [switch]$LogOnly=$false
    )

    # Creating log file if file does not exist in the given path.
    if (!(Test-Path $Path)) {
        Write-Host "Creating $Path"
        $null = New-Item $Path -Force -ItemType File
    }

    # Write message to different levels such as Error, Warning or Info.
    switch ($Level) {
        'Error' {
            if (!$LogOnly) {
                Write-Error $Message
            }

            $LevelText = 'ERROR'
        }
        'Warn' {
            if (!$LogOnly) {
                Write-Warning $Message
            }

            $LevelText = 'WARNING'
        }
        'Info' {
            if (!$LogOnly) {
                Write-Host $Message
            }

            $LevelText = 'INFO'
        }
    }
    # Date and time for log file
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Write log entry to $Path
    "[$Date] [$LevelText] $Message" | Out-File -FilePath $Path -Append
}

# Function to retry a specific ScriptBlock
function ExecuteWithRetries {
    param(

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptToRetry,

        [Parameter(Mandatory=$true)]
        [array] $ArgumentList,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $ErrorMessageOnFailures,

        [Parameter(Mandatory=$false)]
        [string] $MessageIfSucceeded,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int] $NumberOfRetries = 10,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $LogPath,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int] $DurationBeforeNextRetry = 10
    )

    $retryCount = 1
    $lastTrySucceeded = $true

    do {
        if ($retryCount -gt 1) {
            Write-Host "Retrying the operation ($retryCount / $NumberOfRetries)..."
        }

        # Till the last retry, the error is suppressed.
        $lastTrySucceeded = Invoke-Command -ScriptBlock $ScriptToRetry -ArgumentList $ArgumentList

        if ($lastTrySucceeded) {
            if ($MessageIfSucceeded) {
                WriteLog -Path $LogPath -Message $MessageIfSucceeded
            }
        } else {
            if ($retryCount -eq $NumberOfRetries) {
                WriteLog -Path $LogPath -Level Error -Message $Error[0].Exception
            }

            $retryCount++
            Write-Host $ErrorMessageOnFailures
            Start-Sleep -s $DurationBeforeNextRetry
        }
    } while ($lastTrySucceeded -eq $false -and $retryCount -le $NumberOfRetries)
}

# Function to remove SendAs permission from group
function RemoveSendAsPermissionFromGroup {
    param ($groupId, $trustee)

    if ($ArePublicFoldersOnPremises) {
        Remove-RemoteRecipientPermission -Identity $groupId -Trustee $trustee -AccessRights SendAs -confirm:$false
    } else {
        Remove-RecipientPermission -Identity $groupId -Trustee $trustee -AccessRights SendAs -confirm:$false
    }

    return $?
}

# Function to add SendAs permission to public folder
function AddSendAsPermissionToPf {
    param ($primarySmtpOfPf, $trustee)

    Add-RecipientPermission -Identity $primarySmtpOfPf -Trustee $trustee -AccessRights SendAs -confirm:$false
    return $?
}

# Function to add SendOnBehalfTo permission to public folder
function AddSendOnBehalfToPermissionToPf {
    param ($primarySmtpOfPf, $user)

    Set-MailPublicFolder $primarySmtpOfPf -GrantSendOnBehalfTo @{Add=$user }
    return $?
}

# function to enable mail public folder with the properties
function EnableMailPfWithProperties {
    param ($identity, $pfEmailIds, $extAddr)

    $Error[0] = $null
    if ($extAddr) {
        Set-MailPublicFolder $identity -EmailAddresses $pfEmailIds -ExternalEmailAddress $extAddr -EmailAddressPolicyEnabled $false 2> $null
    } else {
        Set-MailPublicFolder $identity -EmailAddresses $pfEmailIds -EmailAddressPolicyEnabled $false 2> $null
    }

    if ($Error[0]) {
        return $false
    } else {
        return $true
    }
}

# Create a tenant PSSession against Exchange Online with modern auth.
function InitializeExchangeOnlineRemoteSession() {
    Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue
    if (Get-Module ExchangeOnlineManagement) {
        $connectParams = @{
            ConnectionUri = $ConnectionUri
            Prefix        = "Remote"
            ErrorAction   = "SilentlyContinue"
        }

        if ($null -ne $Credential) {
            $connectParams.Credential = $Credential
        }
        Connect-ExchangeOnline @connectParams
        $script:isConnectedToExchangeOnline = $true
    } else {
        Write-Warning $LocalizedStrings.EXOV2ModuleNotInstalled
        exit
    }

    WriteLog -Path $logPath -Message $LocalizedStrings.RemoteSessionCreatedSuccessfully
}

####################################################################################################
# Script starts here
####################################################################################################
$script:isConnectedToExchangeOnline = $false

if ($WhatIf) {
    WriteLog -Path $logPath -Message $LocalizedStrings.WhatIfEnabled
}

if ($ArePublicFoldersOnPremises) {
    # E2010 Snap-in is added for Get-RecipientPermission cmdlet.
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010

    Get-RecipientPermission > $null
    if (!$?) {
        # User may not have enough permissions to run Get-RecipientPermission cmdlet.
        WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.UnsuccessfulGetRecipientPermissionCmdlet)
        Remove-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010
        return
    }
}

if ($ArePublicFoldersOnPremises -and ((Get-ExchangeServer $env:COMPUTERNAME -ErrorAction:Stop).AdminDisplayVersion.Major -eq 14)) {
    $isE14OnPrem = $true
} else {
    $isE14OnPrem = $false
}

# If the backup files are not found, script will terminate.
$MissingFiles = @()

if (!(Test-Path $permissionListCsv)) {
    $MissingFiles += $permissionListCsv
}

if (!(Test-Path $pfToGrpMappingCsv)) {
    $MissingFiles += $pfToGrpMappingCsv
}

if (!(Test-Path $pfMailPropCsv)) {
    $MissingFiles += $pfMailPropCsv
}

if ($MissingFiles) {
    $MissingFiles = $MissingFiles -join ", "
    WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.BackupNotFound -f $MissingFiles)
    return
}

#Importing PermissionList and MailProperties of public folders.
WriteLog -Path $logPath -Message $LocalizedStrings.ReadingPfPerms
$accessRights = Import-Csv $permissionListCsv
$pfEmailIdsAndGroup = Import-Csv $pfToGrpMappingCsv

if ($accessRights.Length -eq 0) {
    WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.IncorrectCsv -f $permissionListCsv)
    return
}

if ($pfEmailIdsAndGroup.Length -eq 0) {
    WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.IncorrectCsv -f $pfToGrpMappingCsv)
    return
}

WriteLog -Path $logPath -Message ($LocalizedStrings.ImportingBackupFilesSuccessful -f $permissionListCsv, $pfToGrpMappingCsv)

WriteLog -Path $logPath -Message ($LocalizedStrings.RestoringPfPerms -f $permissionListCsv)

try {
    # if public folders are on-premises, create an EXO remote session
    if ($ArePublicFoldersOnPremises) {
        WriteLog -Path $logPath -Message $LocalizedStrings.CreatingRemoteSession
        InitializeExchangeOnlineRemoteSession
    }

    foreach ($accessRight in $accessRights) {
        $user = ([string]$accessRight.User).ToLower()

        # Checking if the user exists.
        if ($user -ne "default" -and $user -ne "anonymous") {
            $userSmtpAddress = $accessRight.PrimarySmtpAddress

            if ($isE14OnPrem) {
                $uniqueUser = [string] (Get-Recipient $user -ErrorAction SilentlyContinue).Name
            } elseif ($userSmtpAddress) {
                # User existed at the time of lockdown. Checking the user still exists.
                $uniqueUser = [string] (Get-Recipient $userSmtpAddress -ErrorAction SilentlyContinue).Name
            } else {
                # Invalid user from the time of lockdown.
                $uniqueUser = $null
            }

            if (!$uniqueUser) {
                WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.SkippingUser -f $user)
                continue
            }
        } else {
            $uniqueUser = $user
        }

        if ($WhatIf) {
            WriteLog -Path $logPath -Message ($LocalizedStrings.RemovingPfPermission -f $uniqueUser, [string]$accessRight.Identity)
            WriteLog -Path $logPath -Message ($LocalizedStrings.AddPfPermission -f $uniqueUser, [string]$accessRight.AccessRights, [string]$accessRight.Identity)
            continue
        }

        # Removing any current access right for that particular user on that particular public folder, before we add an access right from backup entry.

        if ($isE14OnPrem) {
            # In E14 we need to specify the AccessRight parameter in Remove-PublicFolderClientPermission, whereas in the
            # latest versions the parameter AccessRights is not present.
            $perm = Get-PublicFolderClientPermission -Identity $accessRight.Identity -User $uniqueUser
            if ($perm) {
                Remove-PublicFolderClientPermission -Identity $accessRight.Identity -User $uniqueUser -AccessRights $perm.AccessRights -ErrorAction SilentlyContinue -Confirm:$false
            }
        } else {
            Remove-PublicFolderClientPermission -Identity $accessRight.Identity -User $uniqueUser -ErrorAction SilentlyContinue -Confirm:$false
        }

        # Add the access right from the backup file entry.
        Add-PublicFolderClientPermission -Identity $accessRight.Identity -User $uniqueUser -AccessRights $accessRight.AccessRights.Split()
        if (!$?) {
            WriteLog -Path $logPath -Level Error -LogOnly -Message $Error[0].Exception
        }
    }

    WriteLog -Path $logPath -Message $LocalizedStrings.RestoredPfPerms

    WriteLog -Path $logPath -Message $LocalizedStrings.MailEnablingPfs

    foreach ($pfEmailIdsAndGroupItem in $pfEmailIdsAndGroup) {
        if (!($pfEmailIdsAndGroupItem.EmailAddresses)) {
            # This public folder was not mail enabled at the time of lock down.
            continue
        }

        $pfEmailIds = $pfEmailIdsAndGroupItem.EmailAddresses.Split()
        $identity = $pfEmailIdsAndGroupItem.Identity
        $sendOnBehalfTo = $pfEmailIdsAndGroupItem.GrantSendOnBehalfTo
        $sendOnBehalfToList = $sendOnBehalfTo.Split()

        $sendOnBehalfToAddedByScript = ($pfEmailIdsAndGroupItem.SendOnBehalfToAddedByScript).Split()
        $sendAsAddedByScript = ($pfEmailIdsAndGroupItem.SendAsAddedByScript).Split()

        $extAddr = $pfEmailIdsAndGroupItem.ExternalEmailAddress
        $emailAddressPolicyEnabled = [System.Convert]::ToBoolean($pfEmailIdsAndGroupItem.EmailAddressPolicyEnabled)
        $sendAsList = ($pfEmailIdsAndGroupItem.SendAsList).Split()
        $groupId = $pfEmailIdsAndGroupItem.UnifiedGroup

        if ($WhatIf) {
            WriteLog -Path $logPath -Message ($LocalizedStrings.RemovedPropertiesFromGroup -f $groupId, [string]$SendAsAddedByScript, [string]$sendOnBehalfToAddedByScript, [string]$pfEmailIds)
            WriteLog -Path $logPath -Message ($LocalizedStrings.MailEnabledPf -f $identity)
            WriteLog -Path $logPath -Message ($LocalizedStrings.AddedPropertiesBackToPf -f $identity, [string]$SendAsList, [string]$sendOnBehalfToList, $emailAddressPolicyEnabled)
            continue
        }

        # Removing the public folder smtp addresses from Group's proxy address list.
        if ($ArePublicFoldersOnPremises) {
            Set-RemoteUnifiedGroup $groupId -EmailAddresses @{Remove=$pfEmailIds }
        } else {
            Set-UnifiedGroup $groupId -EmailAddresses @{Remove=$pfEmailIds }
        }
        # Removing SendOnBehalfTo from group, that had assigned at the time of lockdown
        if ($sendOnBehalfToAddedByScript) {
            # Trying whole list (silently) first.
            $Error[0] = $null

            if ($ArePublicFoldersOnPremises) {
                Set-RemoteUnifiedGroup $groupId -GrantSendOnBehalfTo @{Remove=$sendOnBehalfToAddedByScript } 2> $null
            } else {
                Set-UnifiedGroup $groupId -GrantSendOnBehalfTo @{Remove=$sendOnBehalfToAddedByScript } 2> $null
            }

            if ($Error[0]) {
                # There could be one or more invalid users.
                # Trying the list items one by one.
                foreach ($sendOnBehalfToItem in $sendOnBehalfToAddedByScript) {
                    if ($ArePublicFoldersOnPremises) {
                        Set-RemoteUnifiedGroup $groupId -GrantSendOnBehalfTo @{Remove=$sendOnBehalfToItem }
                    } else {
                        Set-UnifiedGroup $groupId -GrantSendOnBehalfTo @{Remove=$sendOnBehalfToItem }
                    }

                    if (!$?) {
                        WriteLog -Path $logPath -Level Error -LogOnly -Message $Error[0].Exception
                    }
                }
            }
        }

        # Removing SendAs permission from the group, that had assigned at the time of lockdown.
        if ($sendAsAddedByScript) {
            $sendAsAddedByScript | ForEach-Object {`
                    ExecuteWithRetries -ScriptToRetry ${function:RemoveSendAsPermissionFromGroup} `
                    -ArgumentList @($groupId, $_) `
                    -ErrorMessageOnFailures ($LocalizedStrings.RemovingSendAsFromGroupFailed -f $groupId) `
                    -NumberOfRetries 3 `
                    -LogPath $logPath; `
            }
        }

        # Mail Enabling public folder.
        Enable-MailPublicFolder -Identity $identity

        ExecuteWithRetries -ScriptToRetry ${function:EnableMailPfWithProperties} `
            -ArgumentList @($identity, $pfEmailIds, $extAddr) `
            -ErrorMessageOnFailures ($LocalizedStrings.RestoringSMTPFailed -f $identity) `
            -MessageIfSucceeded ($LocalizedStrings.RestoringSMTPSucceeded -f $identity) `
            -LogPath $logPath

        # Setting EmailAddressPolicyEnabled to original value.
        Set-MailPublicFolder -Identity $identity -EmailAddressPolicyEnabled $emailAddressPolicyEnabled

        $primarySmtpOfPf = [string](Get-MailPublicFolder $identity).PrimarySmtpAddress

        # Adding SendOnBehalfTo to public folder, that existed at the time of lockdown
        if ($sendOnBehalfToList) {
            # Trying whole list (silently) first
            $Error[0] = $null
            Set-MailPublicFolder $primarySmtpOfPf -GrantSendOnBehalfTo @{Add=$sendOnBehalfToList } 2> $null
            if ($Error[0]) {
                # There could be one or more invalid users.
                # Trying the list items one by one.
                $sendOnBehalfToList | ForEach-Object {`
                        ExecuteWithRetries -ScriptToRetry ${function:AddSendOnBehalfToPermissionToPf} `
                        -ArgumentList @($primarySmtpOfPf, $_) `
                        -ErrorMessageOnFailures ($LocalizedStrings.AddingSendOnBehalfToPermissionFailed -f $primarySmtpOfPf, $_) `
                        -NumberOfRetries 3 `
                        -LogPath $logPath; `
                }
            }
        }

        # Adding SendAs permission to the public folder, that was present at the time of lockdown.
        if ($sendAsList) {
            $sendAsList | ForEach-Object {`
                    ExecuteWithRetries -ScriptToRetry ${function:AddSendAsPermissionToPf} `
                    -ArgumentList @($primarySmtpOfPf, $_) `
                    -ErrorMessageOnFailures ($LocalizedStrings.AddingSendAsToPfFailed -f $identity) `
                    -NumberOfRetries 3 `
                    -LogPath $logPath; `
            }
        }
    }
} finally {
    if ($script:isConnectedToExchangeOnline -and $ArePublicFoldersOnPremises) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Remove-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010
    }
}

if (!$WhatIf) {
    WriteLog -Path $logPath -Message ($LocalizedStrings.MailEnabledAndRestoredProperties -f $identity)
    WriteLog -Path $logPath -Message $LocalizedStrings.PfRecoveryComplete
}
