# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# LockAndSavePublicFolderProperties.ps1
#    It locks down the public folders which are being migrated to Groups, and back up
#    the properties in case the user want to fallback to public folders.
#
# .DESCRIPTION
#    Script performs the following actions
#      1. It saves PublicFolderClientPermissions of migrating public folders.
#      2. It reads permission of each user and assign back the permissions except
#         create, edit or delete permissions.
#      3. Mail-disable and save mail properties of any mail enabled public folder which gets migrated.
#      4. Add smtp addresses of mail public folders to the Proxy Address list of Groups to
#         which each public folder gets migrated.
#
#    After the execution of the script
#      1. All migrating public folders will be read-only to those users who had access to public folder content.
#      2. Any user who didn't had read permission will not gain read permission by lockdown.
#      3. Any mails sent to mail enabled public folder will be routed to target group.
#
# .PARAMETER Credential
#    Exchange Online user name and password. Don't use this param if MFA is enabled.
#
# .PARAMETER MappingCsv
#    The public folder to group mapping csv file which was provided for the migration batch.
#
# .PARAMETER BackupDir
#    The directory to which user want to save the permissions and other properties as backup files.
#
# .PARAMETER ArePublicFoldersOnPremises
#    Tells if public folders are on-premises. Set to '$true' if public folders are remote, else set to '$false'.
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
#    .\LockAndSavePublicFolderProperties.ps1 -MappingCsv .\map.csv -BackupDir C:\PFToGroupMigration\ -WhatIf
#    .\LockAndSavePublicFolderProperties.ps1 -MappingCsv .\map.csv -BackupDir C:\PFToGroupMigration\ -ArePublicFoldersOnPremises $true

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [PSCredential] $Credential,

    [Parameter(Mandatory=$true, ParameterSetName="Default", HelpMessage="The input csv used to create migration batch")]
    [ValidateNotNullOrEmpty()]
    [string] $MappingCsv,

    [Parameter(Mandatory=$true, ParameterSetName="Default", HelpMessage="Choose directory to backup current public folder permissions")]
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

$permissionListFile = Join-Path $BackupDir ($prefix + "PfPermissions.csv")
$pfToGrpMappingCsv  = Join-Path $BackupDir ($prefix + "PfToGroupMapping.csv")
$pfMailPropCsv      = Join-Path $BackupDir ($prefix + "PfMailProperties.csv")
$logPath            = Join-Path $BackupDir ($prefix + "PfLockdown_summary.log")

$updateRolesLookupForLockdown = @{`
        "None"             = "None"; `
        "AvailabilityOnly" = "AvailabilityOnly"; `
        "LimitedDetails"   = "LimitedDetails"; `
        "Contributor"      = "FolderVisible"; `
        "Reviewer"         = "ReadItems", "FolderVisible"; `
        "NonEditingAuthor" = "ReadItems", "FolderVisible"; `
        "Author"           = "ReadItems", "FolderVisible"; `
        "Editor"           = "ReadItems", "FolderVisible"; `
        "PublishingAuthor" = "ReadItems", "CreateSubfolders", "FolderVisible"; `
        "PublishingEditor" = "ReadItems", "CreateSubfolders", "FolderVisible"; `
        "Owner"            = "ReadItems", "CreateSubfolders", "FolderContact", "FolderVisible"; `

}

$allowedListOfPermissionsForCustomRole = "ReadItems", "CreateSubfolders", "FolderContact", "FolderVisible"

$LocalizedStrings = ConvertFrom-StringData @'
WhatIfEnabled = IMPORTANT!!! WhatIf parameter is set, therefore no changes will be made. The messages shown are just a preview of the actual execution. All backup files are created with a 'test_' prefix.
UnsuccessfulGetRecipientPermissionCmdlet = Get-RecipientPermission cmdlet could not be executed. Please make sure the user is a member of role groups 'Organization Management' and 'Recipient Management' and try again.
MappingCsvNotFound = Public folder to group mapping csv is not found. Please verify the provided path {0}.
IncorrectCsvFormat = The mapping csv is either empty or does not have the expected columns. Please ensure that it contains 'FolderPath' and 'TargetGroupMailbox' columns with appropriate values.
BackupCsvAlreadyExist = Backup files already exist. Preventing further execution, as the original permissions of the public folders can be permanently lost. Please provide a different backup location and try again.
ExportingPFPermissions = Exporting public folder permissions..
PfsAlreadyInLockedState = Public folders being migrated are already in locked down state. No action is performed on public folders.
WarnBackupFilesNotFound = Public folder permissions backup file is not found ({0}). Restoring permissions is not possible.
CredentialNotFound = Exchange Online credential not found. Please provide Exchange Online admin credential for the remote PowerShell login.
CreatingRemoteSession = Creating an Exchange Online remote Powershell session...
FailedToCreateRemoteSession = Unable to create a remote PowerShell session to Exchange Online. The error is as follows: '{0}'.
FailedToImportRemoteSession = Exchange Online remote Powershell session could not be imported. The error is as follows: '{0}'.
RemoteSessionCreatedSuccessfully = Exchange Online remote Powershell session created successfully.
ExportPermissionsSuccessful = Successfully saved public folder permissions to {0}.
ExportMailPropertiesSuccessful = Mail properties of mail enabled public folders are successfully saved to {0}.
SkippingUser = Skipping permissions of user {0} as user is not found. The user value in public folder client permission entry could not be resolved.
SkippingNotMigratedUser = Skipping permissions of user {0} as user is not found in Exchange Online.
PfMailDisabled = Public folder {0} is mail disabled.
PfPropertiesCopiedToGroup = The following properties are copied from public folder {0} to Group {1}: SMTP addresses {2}, send on behalf to permission to users {3}.
SettingSMTPToGroupFailed = Setting SMTP address to group failed..
SMTPAddressesCopiedFromMailPfToGroup = SMTP addresses of {0} have been added as proxy addresses to group {1}.
SendAsPermsCopiedToGroup = The SendAs permissions of following users are copied from public folder {0} to group {1}: {2}.
AddingSendAsToGroupFailed = Adding SendAs permission to group failed..
ExportMailPfPropertiesAndGroupSuccessful = Mail properties of mail enabled public folders, along with the groups to which those properties are exported, are successfully saved to {0}.
LockingPfsByRemovingPerms = Locking down migrating public folders by removing permissions..
RemovingPfPerm = Removing permissions of user {0} on public folder {1}.
AddingPfPerm = Adding permissions ({2}) for user {0} on {1}.
LockdownWithReadOnlyPermsSuccessful = Public folders being migrated are successfully locked down with ReadOnly permission.
PfLockdownComplete = Public folder lockdown is complete.
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

# Function to copy email addresses to group
function SetEmailIdsToGroup {
    param ($targetGroupMailbox, $pfEmailIds, $sendOnBehalfTo)

    $Error[0] = $null
    if ($ArePublicFoldersOnPremises) {
        if ($sendOnBehalfTo) {
            Set-RemoteUnifiedGroup $targetGroupMailbox -EmailAddresses @{Add=$pfEmailIds } -GrantSendOnBehalfTo @{Add=$sendOnBehalfTo } 2> $null
        } else {
            Set-RemoteUnifiedGroup $targetGroupMailbox -EmailAddresses @{Add=$pfEmailIds } 2> $null
        }
    } else {
        if ($sendOnBehalfTo) {
            Set-UnifiedGroup $targetGroupMailbox -EmailAddresses @{Add=$pfEmailIds } -GrantSendOnBehalfTo @{Add=$sendOnBehalfTo } 2> $null
        } else {
            Set-UnifiedGroup $targetGroupMailbox -EmailAddresses @{Add=$pfEmailIds } 2> $null
        }
    }

    if ($Error[0]) {
        return $false
    } else {
        return $true
    }
}

# Function to add SendAs permissions of public folder to group
function AddSendAsPermissionToGroup {
    param ($groupId, $trustee)

    $Error[0] = $null
    if ($ArePublicFoldersOnPremises) {
        Add-RemoteRecipientPermission -Identity $groupId -Trustee $trustee -AccessRights SendAs -ErrorAction SilentlyContinue -confirm:$false
    } else {
        Add-RecipientPermission -Identity $groupId -Trustee $trustee -AccessRights SendAs -ErrorAction SilentlyContinue -confirm:$false
    }

    if ($Error[0]) {
        return $false
    } else {
        return $true
    }
}

# Create a tenant PSSession against Exchange Online using modern auth.
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

# Checking the existence of csv file.
if (!(Test-Path $MappingCsv)) {
    WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.MappingCsvNotFound -f $MappingCsv)
    return
}

$pfToGrpMapping = Import-Csv $MappingCsv

# Checking expected columns in the csv provided.
$invalidRows = $pfToGrpMapping | Where-Object { $_.FolderPath -eq $null -or $_.TargetGroupMailbox -eq $null }

if ($invalidRows) {
    WriteLog -Path $logPath -Level Error -Message $LocalizedStrings.IncorrectCsvFormat
    return
}

# Script will exit if the backup files found.
# Preventing careless re-run of the script, as it will lead to loss of actual Permissions backup
# and creating a new backup file of lockdown permissions.
if ((Test-Path $permissionListFile) -or (Test-Path $pfToGrpMappingCsv) -or (Test-Path $pfMailPropCsv)) {
    WriteLog -Path $logPath -Level Error -Message $LocalizedStrings.BackupCsvAlreadyExist
    return
}

WriteLog -Path $logPath -Message $LocalizedStrings.ExportingPFPermissions

# Getting public folder permissions
$pfsBeingMigrated = $pfToGrpMapping | ForEach-Object { $_.FolderPath }
if ($isE14OnPrem) {
    # ADRecipient object is not available in 2010. Hence get the user name from ActiveDirectoryIdentity in the user object.
    $accessRights = $pfsBeingMigrated  | Get-PublicFolderClientPermission | Select-Object Identity,
    AccessRights,
    User,
    @{Name="Name"; Expression= { $_.User.ActiveDirectoryIdentity.Name } }
} else {
    $accessRights = $pfsBeingMigrated  | Get-PublicFolderClientPermission | Select-Object Identity,
    AccessRights,
    User,
    @{Name="Name"; Expression= { $_.User.ADRecipient.Name } },
    @{Name="PrimarySmtpAddress"; Expression= { $_.User.ADRecipient.PrimarySmtpAddress } }
}

# Checking if the public folders are already in locked down state.
# If there's a permission for any public folder with Create/Update/Delete permission,
# we consider that the public folders are not in lockdown state.
$alreadyLockedDown = $true

foreach ($accessRightItem in $accessRights) {
    if ($updateRolesLookupForLockdown.ContainsKey([string]$accessRightItem.AccessRights)) {
        if (!("None", "Reviewer", "AvailabilityOnly", "LimitedDetails" -contains [string]$accessRightItem.AccessRights)) {
            $alreadyLockedDown = $false
            break
        }
    } else {
        # Finding if there is any create/update/delete permission
        $updateAccessRights = $accessRightItem.AccessRights | Where-Object { $allowedListOfPermissionsForCustomRole -notcontains $_ }

        if ($updateAccessRights) {
            $alreadyLockedDown = $false
            break
        }
    }
}

# If the public folders are already locked down, warn the user that the backup file is not found.
if ($alreadyLockedDown) {
    WriteLog -Path $logPath -Message $LocalizedStrings.PfsAlreadyInLockedState
    WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.WarnBackupFilesNotFound -f $permissionListFile)
    return
}

try {
    # if public folders are on-premises, create an EXO remote session
    if ($ArePublicFoldersOnPremises) {
        WriteLog -Path $logPath -Message $LocalizedStrings.CreatingRemoteSession
        InitializeExchangeOnlineRemoteSession
    }

    # Exporting public folder Permissions to default backup location
    $accessRightsToExport = @()
    foreach ($accessRightItem in $accessRights) {
        $row = New-Object PSObject -Property @{
            Identity           = [string] $accessRightItem.Identity
            User               = [string] $accessRightItem.User
            AccessRights       = [string] $accessRightItem.AccessRights
            PrimarySmtpAddress = [string] $accessRightItem.PrimarySmtpAddress
            Name               = [string] $accessRightItem.Name
        }

        $accessRightsToExport += $row
    }

    $accessRightsToExport | Export-Csv $permissionListFile -Encoding UTF8
    WriteLog -Path $logPath -Message ($LocalizedStrings.ExportPermissionsSuccessful -f $PermissionListFile)

    # Exporting mail public folder Properties to default backup location
    $pfToGrpMapping.FolderPath | Get-MailPublicFolder -ErrorAction SilentlyContinue | Export-Csv $pfMailPropCsv -Encoding UTF8
    WriteLog -Path $logPath -Message ($LocalizedStrings.ExportMailPropertiesSuccessful -f $pfMailPropCsv)

    $rows = @()
    foreach ($pfToGrpMappingItem in $pfToGrpMapping) {
        # Obtaining mail properties.
        $mailEnabledPf = (Get-MailPublicFolder $pfToGrpMappingItem.FolderPath -ErrorAction SilentlyContinue) | Select-Object EmailAddresses,
        ExternalEmailAddress,
        EmailAddressPolicyEnabled,
        GrantSendOnBehalfTo,
        PrimarySmtpAddress
        # If public folder is mail enabled
        if ($mailEnabledPf) {
            $pfEmailIds     = $mailEnabledPf.EmailAddresses
            $extEmailAddr   = $mailEnabledPf.ExternalEmailAddress
            $primarySmtpAddr= [string]$mailEnabledPf.PrimarySmtpAddress
            $sendOnBehalfTo = $mailEnabledPf.GrantSendOnBehalfTo | ForEach-Object { [string](Get-Recipient $_).PrimarySmtpAddress }
            $sendAsList     = Get-RecipientPermission $primarySmtpAddr -ErrorAction SilentlyContinue | ForEach-Object { $_.Trustee } | Get-Recipient | ForEach-Object { [string]$_.PrimarySmtpAddress }
            $folderPath     = $pfToGrpMappingItem.FolderPath
            $groupId        = $pfToGrpMappingItem.TargetGroupMailbox

            # Converting type of primary smtp address from "SMTP" to "smtp" to avoid replacing
            # group's primary smtp address.
            $pfEmailIds = $pfEmailIds | ForEach-Object { "smtp:" + ([string]$_).Split(":")[1] }
            if ($isE14OnPrem) {
                # We can't set the externalEmailAddress for mail-enabled public folder in E14
                $extEmailAddr = $null
            }

            # SendAs and SendOnBehalfTo permissions that are not already present in group.
            if ($ArePublicFoldersOnPremises) {
                $sendAsOfGroup = Get-RemoteRecipientPermission $groupId | ForEach-Object { $_.Trustee } | Get-RemoteRecipient | ForEach-Object { $_.PrimarySmtpAddress }
                $sendAsAddedByScript = $sendAsList | Where-Object { $sendAsOfGroup -notcontains $_ }

                $sendOnBehalfToOfGroup = (Get-RemoteUnifiedGroup $groupId).GrantSendOnBehalfTo | ForEach-Object { Get-RemoteRecipient $_ -ErrorAction SilentlyContinue } | ForEach-Object { [string] $_.PrimarySmtpAddress }
                $sendOnBehalfToAddedByScript = $sendOnBehalfTo | Where-Object { $sendOnBehalfToOfGroup -notcontains $_ }

                $migratedUserListOfSendOnBehalfTo = @()
                foreach ($user in $sendOnBehalfToAddedByScript) {
                    $migratedUser = Get-RemoteRecipient $user -ErrorAction SilentlyContinue
                    if (!$migratedUser) {
                        WriteLog -Path $logPath -Level Warn ($LocalizedStrings.SkippingNotMigratedUser -f $user)
                    } else {
                        $migratedUserListOfSendOnBehalfTo += $user
                    }
                }

                $sendOnBehalfToAddedByScript = $migratedUserListOfSendOnBehalfTo

                $migratedUserListOfSendAs = @()
                foreach ($user in $sendAsAddedByScript) {
                    $migratedUser = Get-RemoteRecipient $user -ErrorAction SilentlyContinue
                    if (!$migratedUser) {
                        WriteLog -Path $logPath -Level Warn ($LocalizedStrings.SkippingNotMigratedUser -f $user)
                    } else {
                        $migratedUserListOfSendAs += $user
                    }
                }

                $sendAsAddedByScript = $migratedUserListOfSendAs
            } else {
                $sendAsOfGroup = ([string] (Get-RecipientPermission $groupId).Trustee).Split()
                $sendAsAddedByScript = $sendAsList | Where-Object { $sendAsOfGroup -notcontains $_ }

                $sendOnBehalfToOfGroup = ([string] (Get-UnifiedGroup $groupId).GrantSendOnBehalfTo).Split()
                $sendOnBehalfToAddedByScript = $sendOnBehalfTo | Where-Object { $sendOnBehalfToOfGroup -notcontains $_ }
            }

            # Mail-Disabling public folder
            if (!$WhatIf) {
                Disable-MailPublicFolder $folderPath -Confirm:$false
            }

            WriteLog -Path $logPath -Message ($LocalizedStrings.PfMailDisabled -f $folderPath)

            # Retry loop for assigning email ids group
            if ($WhatIf) {
                WriteLog -Path $logPath -Message ($LocalizedStrings.PfPropertiesCopiedToGroup -f $folderPath, $groupId, [string]$pfEmailIds, [string]$sendOnBehalfToAddedByScript)
            } else {
                ExecuteWithRetries -ScriptToRetry:${function:SetEmailIdsToGroup} `
                    -ArgumentList:@($groupId, $pfEmailIds, $sendOnBehalfToAddedByScript) `
                    -ErrorMessageOnFailures:$LocalizedStrings.SettingSMTPToGroupFailed `
                    -MessageIfSucceeded:($LocalizedStrings.SMTPAddressesCopiedFromMailPfToGroup -f $folderPath, $groupId) `
                    -LogPath:$logPath
            }

            # Retry loop for giving SendAs permission of mail-enabled public folder to corresponding group
            if ($sendAsAddedByScript) {
                if ($WhatIf) {
                    WriteLog -Path $logPath -Message ($LocalizedStrings.SendAsPermsCopiedToGroup -f $folderPath, $groupId, [string]$sendAsAddedByScript)
                } else {
                    $sendAsAddedByScript | ForEach-Object {`
                            ExecuteWithRetries -ScriptToRetry ${function:AddSendAsPermissionToGroup} `
                            -ArgumentList @($groupId, $_) `
                            -ErrorMessageOnFailures $LocalizedStrings.AddingSendAsToGroupFailed `
                            -NumberOfRetries 3 `
                            -LogPath $logPath; `
                    }
                }
            }
        } else {
            # Removing the value of any mail property variable, in case of a non-mail public folder
            $pfEmailIds                  = $null
            $extEmailAddr                = $null
            $sendOnBehalfTo              = $null
            $sendAsList                  = $null
            $sendOnBehalfToAddedByScript = $null
            $sendAsAddedByScript         = $null
        }

        $row = New-Object PSObject -Property @{
            Identity                    = $pfToGrpMappingItem.FolderPath
            EmailAddresses              = $pfEmailIds -join " "
            UnifiedGroup                = $pfToGrpMappingItem.TargetGroupMailbox
            ExternalEmailAddress        = $extEmailAddr
            EmailAddressPolicyEnabled   = $mailEnabledPf.EmailAddressPolicyEnabled
            GrantSendOnBehalfTo         = $sendOnBehalfTo -join " "
            SendAsList                  = $sendAsList -join " "
            SendOnBehalfToAddedByScript = $sendOnBehalfToAddedByScript -join " "
            SendAsAddedByScript         = $sendAsAddedByScript -join " "
        }

        $rows += $row
    }

    # Exporting PF Identity, Group Identity, Mail properties of PF to default location.
    $rows | Export-Csv $pfToGrpMappingCsv -Encoding UTF8

    WriteLog -Path $logPath -Message ($LocalizedStrings.ExportMailPfPropertiesAndGroupSuccessful -f $pfToGrpMappingCsv)

    WriteLog -Path $logPath -Message $LocalizedStrings.LockingPfsByRemovingPerms

    # We update the permissions of every custom role or predefined role in a way that
    # 1. No user will have create/update/delete permission on contents
    # 2. If the user didn't had access to read the contents, it stays same even after lockdown.
    # 3. Permissions assigned will be a subset of {"ReadItems", "CreateSubfolders", "FolderContact", "FolderVisible"}
    foreach ($accessRightItem in $accessRights) {
        if ($updateRolesLookupForLockdown.ContainsKey([string]$accessRightItem.AccessRights)) {
            $newAccessRights = $updateRolesLookupForLockdown.Get_Item([string]$accessRightItem.AccessRights)
        } else {
            $newAccessRights = $accessRightItem.AccessRights | Where-Object { $allowedListOfPermissionsForCustomRole -contains $_ }
            if (!($newAccessRights)) {
                $newAccessRights = "None"
            }
        }

        $user = [string] $accessRightItem.User
        $identity = $accessRightItem.Identity

        # Checking if the user exists.
        if ($user -ne "default" -and $user -ne "anonymous") {
            $uniqueUser = $accessRightItem.Name

            if (!$uniqueUser) {
                WriteLog -Path $logPath -Level Warn ($LocalizedStrings.SkippingUser -f $user)
                continue
            }
        } else {
            $uniqueUser = $user
        }

        if ($WhatIf) {
            WriteLog -Path $logPath -Message ($LocalizedStrings.RemovingPfPerm -f $user, $identity)
            WriteLog -Path $logPath -Message ($LocalizedStrings.AddingPfPerm -f $user, $identity, [string]$newAccessRights)
        } else {
            WriteLog -Path $logPath -LogOnly -Message ($LocalizedStrings.RemovingPfPerm -f $user, $identity)

            if ($isE14OnPrem) {
                # E14 demands the parameter AccessRights in Remove-PublicFolderClientPermission cmdlet
                Remove-PublicFolderClientPermission -Confirm:$false -Identity $identity -User $uniqueUser -AccessRights $accessRightItem.AccessRights
            } else {
                # Later versions of Exchange don't have the parameter AccessRight in Remove-PublicFolderClientPermission cmdlet
                Remove-PublicFolderClientPermission -Confirm:$false -Identity $identity -User $uniqueUser
            }

            WriteLog -Path $logPath -LogOnly -Message ($LocalizedStrings.AddingPfPerm -f $user, $identity, [string]$newAccessRights)
            Add-PublicFolderClientPermission -Identity $identity -User $uniqueUser -AccessRights $newAccessRights
        }
    }
} finally {
    if ($script:isConnectedToExchangeOnline -and $ArePublicFoldersOnPremises) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Remove-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010
    }
}

if (!$WhatIf) {
    WriteLog -Path $logPath -Message $LocalizedStrings.LockdownWithReadOnlyPermsSuccessful
    WriteLog -Path $logPath -Message $LocalizedStrings.PfLockdownComplete
}
