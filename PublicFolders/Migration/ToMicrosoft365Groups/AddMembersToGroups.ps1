# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# AddMembersToGroups.ps1
#    This script reads the permission entries for each public folder (from the backup file if the public folders are locked) and
#    adds the users with specific permission entries as either owner/member to the respective group based on their access rights.
#
# .DESCRIPTION
#    1. It reads the permission entries from the backup file stored during lock down if public folders are locked, else uses 'Get-PublicFolderClientPermission' to get the permissions.
#    2. It adds the users with permission roles, "Owner, PublishingEditor, Editor, PublishingAuthor, Author" as members to the group
#    3. It also adds users having at least "ReadItems, CreateItems, FolderVisible, EditOwnedItems, DeleteOwnedItems" access rights as members to the corresponding group.
#    4. It adds the users with permission role, "Owner" as owners to the group.
#    5. It throws a warning when the default permission is Author and above, suggesting the user to make the group 'public'.
#
# .PARAMETER Credential
#    Exchange Online user name and password. Don't use this param if MFA is enabled.
#
# .PARAMETER MappingCsv
#    The public folder to group mapping csv file which was used to create the migration batch.
#
# .PARAMETER ArePublicFoldersLocked
#    Tells if public folders are locked. Set to '$true' if public folders are locked, else set to '$false'.
#
# .PARAMETER BackupDir
#    The directory to which user want to save the logs and read permissions from the back up file, if public folders are locked.
#
# .PARAMETER ArePublicFoldersOnPremises
#    Tells if public folders are on-premises. Set to '$true' if public folders are on premises, else set to '$false'.
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
#    .\AddMembersToGroups.ps1 -MappingCsv PFToGroupMap.csv -ArePublicFoldersLocked $true -BackupDir "C:\PFToGroupMigration\"
#
#    This example shows how to invoke the script when public folders are in exchange online
#
# .EXAMPLE
#    .\AddMembersToGroups.ps1 -MappingCsv PFToGroupMap.csv -ArePublicFoldersLocked $false -BackupDir "C:\PFToGroupMigration\" -ArePublicFoldersOnPremises $true -ConnectionUri "https://partner.outlook.cn/PowerShell"
#
#    This example shows how to invoke the script when public folders are on-premises
#
# .EXAMPLE
#    .\AddMembersToGroups.ps1 -MappingCsv PFToGroupMap.csv -ArePublicFoldersLocked $false -BackupDir "C:\PFToGroupMigration\" -ArePublicFoldersOnPremises $true -ConnectionUri "https://partner.outlook.cn/PowerShell" -WhatIf
#
#    This example shows how to use the 'WhatIf' parameter.

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [PSCredential] $Credential,

    [Parameter(Mandatory = $true, ParameterSetName="Default", HelpMessage = "Mapping csv used to create the migration batch")]
    [ValidateNotNullOrEmpty()]
    [string] $MappingCsv,

    [Parameter(Mandatory = $false, ParameterSetName="Default", HelpMessage = "Enter '`$true' if public folders are locked")]
    [bool] $ArePublicFoldersLocked = $false,

    [Parameter(Mandatory = $true, ParameterSetName="Default", HelpMessage = "Directory to write log and read permissions of locked public folders from back up file")]
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

# Returns the members of the security group
function GetMembersOfSecurityGroup() {
    param ($securityGroup)

    $securityGroup = Get-DistributionGroup $securityGroup | Where-Object { $_.Name -like $securityGroup }
    $securityGroupMembers = Get-DistributionGroupMember $securityGroup.PrimarySmtpAddress.ToString() | Select-Object Name, PrimarySmtpAddress, RecipientType

    if (!$?) {
        WriteLog -Path $logPath -Level Error -LogOnly -Message $error[0]
    }

    return $securityGroupMembers
}

# Adds the user to the dictionary, UniqueUserList along with the details, if the user is a SecurityGroup/ValidUser/InvalidUser,
# Returns $true when the user is of invalid recipient type and does not add such users to UniqueUserList
function AddUserToList() {
    param ([string]$user, [string]$smtpAddress, [string]$userType, [string]$accessRight)

    if ($smtpAddress) {
        #Check if it is a security group
        if ($userType -eq [RecipientType]::MailUniversalSecurityGroup) {
            $UniqueUserList.Add($user, [UserDetails]::SecurityGroup)
        } elseif (($userType -eq [RecipientType]::UserMailbox) -or ($userType -eq [RecipientType]::MailUser)) {
            $UniqueUserList.Add($user, [UserDetails]::ValidUser)
            $SmtpAddressOfUsers.Add($user, $smtpAddress)
        } else {
            WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.InvalidRecipientType -f $user, $userType, $accessRight)
            return $true
        }
    } else {
        # When smtp address is null, it implies that the user does not exist
        $UniqueUserList.Add($user, [UserDetails]::InvalidUser)
    }

    return $false
}

# Checks if the user is in exchange online and adds the user to list
function ValidateAndAddRemoteUserToList() {
    param ([string]$user, [string]$smtpAddress, [string]$userType, [string]$accessRight)

    # Using smtp address for uniqueness as "Name" will not be unique across on-premises and exchange online
    $recipient = Get-RemoteRecipient $smtpAddress -ErrorAction SilentlyContinue | Where-Object { $_.PrimarySmtpAddress -like $smtpAddress } | Select-Object RecipientType

    if ($recipient) {
        $userType = $recipient.RecipientType
    } else {
        $smtpAddress = $null
    }

    return AddUserToList -user $user -smtpAddress $smtpAddress -userType $userType -accessRight $accessRight
}

# Validates the user and adds the user to list
function ValidateAndAddUserToList() {
    param ([string]$user, [string]$smtpAddress, [string]$userType, [string]$accessRight)

    if ($smtpAddress) {
        $recipient = Get-Recipient $smtpAddress -ErrorAction SilentlyContinue | Where-Object { $_.PrimarySmtpAddress -like $smtpAddress } | Select-Object PrimarySmtpAddress, RecipientType
    } else {
        $recipient = Get-Recipient $user -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $user } | Select-Object PrimarySmtpAddress, RecipientType
    }

    if ($recipient) {
        if (!$smtpAddress) {
            $smtpAddress = $recipient.PrimarySmtpAddress.ToString()
        }

        # User type will be null when public folders are locked and permissions are read from the back up file
        # (as user/recipient type is not stored during lockdown).
        if (!$userType) {
            $userType = $recipient.RecipientType
        }

        if ($ArePublicFoldersOnPremises) {
            if ($userType -ne [RecipientType]::MailUniversalSecurityGroup) {
                return ValidateAndAddRemoteUserToList -user $user -smtpAddress $smtpAddress -userType $userType -accessRight $accessRight
            }
        }
    } else {
        $smtpAddress = $null
    }

    return AddUserToList -user $user -smtpAddress $smtpAddress -userType $userType -accessRight $accessRight
}

# Returns true if the user has enough access right to be added as member of the group, else returns false
function IsAccessRightSufficient() {
    param ($accessRights)

    if ($accessRights.Count -eq 1) {
        if ($EligibleRoles -contains $accessRights) {
            return $true
        }

        return $false
    }

    $missingAccessRights = $NecessaryAccessRightsForMember | Where-Object { $accessRights -notcontains $_ }
    if ($missingAccessRights) {
        # One or more access rights required for the user to be added as a member is missing. Hence, return false
        return $false
    }

    return $true
}

# Processes each permission entry and decides if the user needs to be added as a member or owner to the group
function ProcessPermissionEntry() {
    param ([string]$user, [string]$validUser, $accessRights, $owners, $members)

    if ($validUser -eq [UserDetails]::ValidUser) {
        if (IsAccessRightSufficient $accessRights) {
            # Users having 'owner' permission on the pf will be added as Owners to the group.
            # Users having other access rights will be added as members to the group.
            $smtpAddress = $SmtpAddressOfUsers[$user]
            $members.Add($smtpAddress) > $null
            if ($accessRights.Contains("Owner")) {
                $owners.Add($smtpAddress) > $null
            }
        } else {
            # Users with access right None/FolderVisible/CreateSubfolders should be skipped.
            WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.UserSkipped -f $user, [string] $accessRights)
        }
    } else {
        WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.InvalidUser -f $user, [string] $accessRights)
    }
}

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

################ DECLARING GLOBAL VARIABLES ################
$script:isConnectedToExchangeOnline = $false
$permissionListCsvPath = Join-Path $BackupDir "PfPermissions.csv"
$logPath = Join-Path $BackupDir "AddMembersToGroupsNew-log.log"

# Creating a dictionary to store the users and their validity
$UniqueUserList = @{}

# Creating a dictionary to store the users and their validity
$SmtpAddressOfUsers = @{}

# List of roles that make the user eligible to be added as a member of the group
$EligibleRoles = @("Owner", "PublishingEditor", "Editor", "PublishingAuthor", "Author")

# List of access rights that are necessary for a user to be added as a member of the group
$NecessaryAccessRightsForMember = @("ReadItems", "CreateItems", "FolderVisible", "EditOwnedItems", "DeleteOwnedItems")

Add-Type -TypeDefinition @"
   public enum UserDetails
   {
       SecurityGroup,
       ValidUser,
       InvalidUser
   }
"@

Add-Type -TypeDefinition @"
   public enum RecipientType
   {
       MailUniversalSecurityGroup,
       UserMailbox,
       MailUser
   }
"@

$LocalizedStrings = ConvertFrom-StringData @'
MappingCsvNotFound = Public folder to Groups Mapping csv is not found. Please verify the provided path.
IncorrectCsv = The mapping csv is either empty or does not have the expected columns. Please ensure that it contains 'FolderPath' and 'TargetGroupMailbox' columns with appropriate values.
CredentialNotFound = Exchange Online credential not found. Please provide Exchange Online admin credential for the remote PowerShell login.
CreatingRemoteSession = Creating an Exchange Online remote PowerShell session...
FailedToCreateRemoteSession = Unable to create a remote PowerShell session to Exchange Online. The error is as follows: "{0}".
FailedToImportRemoteSession = Exchange Online remote PowerShell session could not be imported. The error is as follows: "{0}".
RemoteSessionCreatedSuccessfully = Exchange Online remote PowerShell session created successfully.
PermissionFileMissing = Back up permission file "PfPermissions.csv" missing in directory {0}! Please provide the correct path and try again. If public folders are not locked, please set 'ArePublicFoldersLocked' to '$false'.
ReadingPermissionsFromFile = Reading permissions from file, {0}.
ReadingPermissions = Getting permissions of public folders.
PermissionEntriesMissingInFile = No permission entries are found in file '{0}' for public folder '{1}'! Please check if the correct file exists in the path provided and try again. If public folders are not locked, please set 'ArePublicFoldersLocked' to '$false'.
PermissionEntriesMissing = No permission entries are found for the public folder '{0}'.
FolderHasOnlyDefaultPermissions = The public folder '{0}' has no permission entries for users, other than 'Default' and 'Anonymous'. Hence no members are added to the group '{1}'.
AddingMembersToGroup = Adding members and owners to the group, '{0}' based on the permission entries of public folder, {1}.
InvalidRecipientType = Skipping user with invalid recipient type! User-{0}; RecipientType-{1}; AccessRight-{2}.
UserSkipped = The user '{0}' has access rights '{1}' which isn't sufficient to be added as a member to the group, hence skipping the user.
InvalidUser = Skipping the user '{0}' with access right '{1}', as the user does not exist!
UserNameIsNull = User with DisplayName '{0}' not found (user name is null).
SecurityGroupHasNoMembers = The security group '{0}' has no members.
AddingMembersAndOwners =  Updating links of the group '{0}' by adding the following list of users as members and owners of the group respectively. Members - '{1}'; Owners - '{2}'.
DefaultPermissionNotNone = Default permission for the public folder '{0}' is '{1}', but only users with explicit permission entries were added as members to the group '{2}'. Please change the privacy setting of the group to 'Public' if you need it to be accessible to everyone.
AddingMembersSuccessful = All the users with explicit permissions (except None, FolderVisible, and CreateSubFolders) to access input public folders have been added as Owners/Members to the respective group successfully!
CommandToAddMembers = Note: Please use the following cmdlet to add new members to the group if required. 'Add-UnifiedGroupLinks -Identity <Group> -LinkType [Owners | Members] -Links <list of users>'.
EXOV2ModuleNotInstalled = This script uses modern authentication to connect to Exchange Online and requires EXO V2 module to be installed. Please follow the instructions at https://docs.microsoft.com/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module to install EXO V2 module.
'@

################ END OF DECLARATION #################

if (!(Test-Path $MappingCsv)) {
    WriteLog -Path $logPath -Level Error -Message $LocalizedStrings.MappingCsvNotFound
    return
}

# Load and validate the mapping csv
$pfToGrpMapping = Import-Csv $MappingCsv

$invalidRows = $pfToGrpMapping | Where-Object { $_.FolderPath -eq $null -or $_.TargetGroupMailbox -eq $null }
if ($invalidRows) {
    WriteLog -Path $logPath -Level Error -Message $LocalizedStrings.IncorrectCsv
    return
}

try {
    # If the public folders are on-premises, create an exchange online remote session
    if ($ArePublicFoldersOnPremises) {
        WriteLog -Path $logPath -Message $LocalizedStrings.CreatingRemoteSession
        InitializeExchangeOnlineRemoteSession
    }

    # If the public folders are locked, check for the back up file with permission list and read the permissions from the file,
    # else get the permissions using, "GetPublicFolderClientPermission"
    if ($ArePublicFoldersLocked) {
        if (!(Test-Path $permissionListCsvPath)) {
            WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.PermissionFileMissing -f $BackupDir)
            return
        }

        WriteLog -Path $logPath -Message ($LocalizedStrings.ReadingPermissionsFromFile -f $permissionListCsvPath)
        $PermissionList = Import-Csv $permissionListCsvPath
    } else {
        WriteLog -Path $logPath -Message $LocalizedStrings.ReadingPermissions
        $pfsBeingMigrated = $pfToGrpMapping | ForEach-Object { $_.FolderPath }

        if ($ArePublicFoldersOnPremises -and ((Get-ExchangeServer $env:COMPUTERNAME -ErrorAction:Stop).AdminDisplayVersion.Major -eq 14)) {
            # ADRecipient object is not available in 2010. Hence get the user name from ActiveDirectoryIdentity in the user object.
            $PermissionList = $pfsBeingMigrated | Get-PublicFolderClientPermission | Select-Object Identity,
            AccessRights,
            User,
            @{Name="Name"; Expression= { $_.User.ActiveDirectoryIdentity.Name } }
        } else {
            $PermissionList = $pfsBeingMigrated | Get-PublicFolderClientPermission | Select-Object Identity,
            AccessRights,
            User,
            @{Name="Name"; Expression= { $_.User.ADRecipient.Name } },
            @{Name="PrimarySmtpAddress"; Expression= { $_.User.ADRecipient.PrimarySmtpAddress } },
            @{Name="RecipientType"; Expression= { $_.User.ADRecipient.RecipientType } }
        }
        if (!$?) {
            WriteLog -Path $logPath -Level Error -LogOnly -Message $error[0]
        }
    }

    # Process the permission entries of each public folder in the mapping csv and add members to the respective group
    foreach ($pfEmailIdsAndGroupItem in $pfToGrpMapping) {
        $pfIdentity = $pfEmailIdsAndGroupItem.FolderPath
        $group = $pfEmailIdsAndGroupItem.TargetGroupMailbox

        WriteLog -Path $logPath -Message ($LocalizedStrings.AddingMembersToGroup -f $group, $pfIdentity)

        # Get permission entries for the public folder being processed
        $permissionEntries = $PermissionList | Where-Object { [string]$_.Identity -eq $pfIdentity }
        if (!$permissionEntries) {
            if ($ArePublicFoldersLocked) {
                WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.PermissionEntriesMissingInFile -f $permissionListCsvPath, $pfIdentity)
            } else {
                WriteLog -Path $logPath -Level Error -Message ($LocalizedStrings.PermissionEntriesMissing -f $pfIdentity)
            }

            continue
        }

        $accessRightsOfSpecificUsers = $permissionEntries | Where-Object { !([string]$_.User -eq "Default" -or [string]$_.User -eq "Anonymous") }
        if (!$accessRightsOfSpecificUsers) {
            WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.FolderHasOnlyDefaultPermissions -f $pfIdentity, $group)
        }

        # List of users to be added as owners of the group
        $owners = New-Object System.Collections.Generic.HashSet[string]

        # List of users to be added as members of the group
        $members = New-Object System.Collections.Generic.HashSet[string]

        # Dictionary of security groups and their access rights to be processed after processing the explicit permissions
        $securityGroups = @{}

        # List of users having explicit permissions
        $usersWithExplicitPermission = New-Object System.Collections.Generic.HashSet[string]

        foreach ($permission in $accessRightsOfSpecificUsers) {
            $user = [string] $permission.User
            $accessRights = $permission.AccessRights
            $userName = $permission.Name
            $smtpAddress = $permission.PrimarySmtpAddress
            $userType = [string] $permission.RecipientType

            # When the userName for a user is null, it implies that ADRecipient or ActiveDirectoryIdentity for the user is not available and the user is invalid
            if (!$userName) {
                WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.InvalidUser -f $user, [string] $accessRights)
                WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.UserNameIsNull -f $user)
                continue
            }

            if (!$UniqueUserList.ContainsKey($userName)) {
                if ($ArePublicFoldersLocked) {
                    $isUserTypeInvalid = ValidateAndAddUserToList -user $userName -smtpAddress $smtpAddress -userType $userType -accessRight $accessRights
                } else {
                    if ($ArePublicFoldersOnPremises -and ($userType -ne [RecipientType]::MailUniversalSecurityGroup)) {
                        if ($smtpAddress) {
                            # Validate the user in exchange online and add the user to list
                            $isUserTypeInvalid = ValidateAndAddRemoteUserToList -user $userName -smtpAddress $smtpAddress -userType $userType -accessRight $accessRights
                        } else {
                            # Run Get-Recipient first to get the smtpAddress
                            # smtpAddress will be null in 2010 as ADRecipient object is not available.
                            $isUserTypeInvalid = ValidateAndAddUserToList -user $userName -smtpAddress $smtpAddress -userType $userType -accessRight $accessRights
                        }
                    } else {
                        $isUserTypeInvalid = AddUserToList -user $userName -smtpAddress $smtpAddress -userType $userType -accessRight $accessRights
                    }
                }
            }

            # Skip users with invalid recipient type
            if ($isUserTypeInvalid) {
                continue
            }

            $userType = $UniqueUserList[$userName]
            if ($userType -eq [UserDetails]::SecurityGroup) {
                $securityGroups.Add($userName, $accessRights)
            } else {
                $usersWithExplicitPermission.Add($userName) > $null
                ProcessPermissionEntry -user $userName -validUser $userType -accessRights $accessRights -owners $owners -members $members
            }
        }

        foreach ($key in $securityGroups.Keys) {
            $securityGroupMembers = GetMembersOfSecurityGroup($key)
            if (!$securityGroupMembers) {
                WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.SecurityGroupHasNoMembers -f $key)
            }

            for ($i = 0; $i -lt $securityGroupMembers.count; $i++) {
                $member = $securityGroupMembers[$i]
                $user = [string] $member.name

                # Do not process those users in security groups, who have explicit permissions.
                if ($usersWithExplicitPermission.Contains($user)) {
                    continue
                }

                if ([string] $member.RecipientType -eq [RecipientType]::MailUniversalSecurityGroup) {
                    # Add members of the nested security group to list
                    $securityGroupMembers += GetMembersOfSecurityGroup($user)
                    continue
                }

                if (!$UniqueUserList.ContainsKey($user)) {
                    if ($ArePublicFoldersOnPremises) {
                        # Validate if the user exists in Remote before adding it to the list
                        $isUserTypeInvalid = ValidateAndAddRemoteUserToList -user $user -smtpAddress $member.PrimarySmtpAddress -userType $member.RecipientType -accessRight $securityGroups[$key]
                    } else {
                        # "Get-DistributionGroupMembers" returns only those members who exist
                        # Hence validation is not required and user can be added to the list directly
                        $isUserTypeInvalid = AddUserToList -user $user -smtpAddress $member.PrimarySmtpAddress -userType $member.RecipientType -accessRight $securityGroups[$key]
                    }
                }

                # Skip users with invalid recipient type
                if ($isUserTypeInvalid) {
                    continue
                }

                ProcessPermissionEntry -user $user -validUser $UniqueUserList[$user] -accessRights $securityGroups[$key] -owners $owners -members $members
            }
        }

        if ($WhatIf) {
            WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.AddingMembersAndOwners -f $group, $members, $owners)
            continue
        }

        # Add members and owners to the group
        WriteLog -Path $logPath -LogOnly -Message ($LocalizedStrings.AddingMembersAndOwners -f $group, $members, $owners)
        if ($null -ne $members) {
            if ($ArePublicFoldersOnPremises) {
                Add-RemoteUnifiedGroupLinks -Identity $group -LinkType Members -Links $members
            } else {
                Add-UnifiedGroupLinks -Identity $group -LinkType Members -Links $members
            }

            if (!$?) {
                WriteLog -Path $logPath -Level Error -LogOnly -Message $error[0]
            }
        }

        if ($null -ne $owners) {
            if ($ArePublicFoldersOnPremises) {
                Add-RemoteUnifiedGroupLinks -Identity $group -LinkType Owners -Links $owners
            } else {
                Add-UnifiedGroupLinks -Identity $group -LinkType Owners -Links $owners
            }

            if (!$?) {
                WriteLog -Path $logPath -Level Error -LogOnly -Message $error[0]
            }
        }

        $default = $permissionEntries | Where-Object { [string]$_.User -eq "Default" }
        if (IsAccessRightSufficient $default.AccessRights) {
            WriteLog -Path $logPath -Level Warn -Message ($LocalizedStrings.DefaultPermissionNotNone -f $pfIdentity, [string] $default.AccessRights, $group)
        }
    }
} finally {
    if ($script:isConnectedToExchangeOnline -and $ArePublicFoldersOnPremises) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
}

WriteLog -Path $logPath -Message $LocalizedStrings.AddingMembersSuccessful
WriteLog -Path $logPath -Message $LocalizedStrings.CommandToAddMembers
