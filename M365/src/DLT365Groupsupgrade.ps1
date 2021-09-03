# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Clear-Host
#Create working folder on the logged user desktop
$ts = Get-Date -Format yyyyMMdd_HHmmss
$ExportPath = "$env:USERPROFILE\Desktop\PowershellDGUpgrade\DlToO365GroupUpgradeChecks_$ts"
mkdir $ExportPath -Force | Out-Null
Add-Content -Path $ExportPath\DlToO365GroupUpgradeCheckslogging.csv  -Value '"Function","Description","Status"'
$Script:Conditionsfailed = 0
Function log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentStatus,

        [Parameter(Mandatory = $true)]
        [string]$Function,

        [Parameter(Mandatory = $true)]
        [string]$CurrentDescription

    )

    $PSobject = New-Object PSObject
    $PSobject | Add-Member -NotePropertyName "Function" -NotePropertyValue $Function
    $PSobject | Add-Member -NotePropertyName "Description" -NotePropertyValue $CurrentDescription
    $PSobject | Add-Member -NotePropertyName "Status" -NotePropertyValue $CurrentStatus
    $PSobject | Export-Csv $ExportPath\DlToO365GroupUpgradeCheckslogging.csv -NoTypeInformation -Append
}
Function Connect2EXO {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$UserCredential)
    try {
        #Validate EXO V2 is installed
        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -eq 1) {
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Importing EXO V2 Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Importing EXO V2 Module" -CurrentDescription $CurrentDescription
            Connect-ExchangeOnline -Credential $UserCredential -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
            Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
        } else {
            #log failure and try to install EXO V2 module then Connect to EXO
            Write-Host "ExchangeOnlineManagement Powershell Module is missing `n Trying to install the module" -ForegroundColor Red
            Install-Module -Name ExchangeOnlineManagement -Force -ErrorAction Stop -Scope CurrentUser
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Installing & Importing EXO V2 powershell module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Installing & Importing EXO V2 powershell module" -CurrentDescription $CurrentDescription
            Connect-ExchangeOnline -Credential $UserCredential -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        }
    } catch {
        $CurrentDescription = "Connecting to EXO V2 please check if ExchangeOnlineManagement Powershell Module is installed & imported"
        $CurrentStatus = "Failure"
        log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        break
    }
}
#Check if Distribution Group can't be upgraded because Member*Restriction is set to "Closed"
Function Debugmemberrestriction {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup

    )
    $MemberJoinRestriction = $Distgroup.MemberJoinRestriction.ToLower().ToString()
    $MemberDepartRestriction = $Distgroup.MemberDepartRestriction.ToLower().ToString()
    if ($MemberDepartRestriction -eq "closed" -or $MemberJoinRestriction -eq "closed") {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded cause either MemberJoinRestriction or MemberDepartRestriction or both values are set to Closed!" -ForegroundColor Red
        "Distribution Group can't be upgraded cause either MemberJoinRestriction or MemberDepartRestriction or both values are set to Closed!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because it is DirSynced
Function Debugdirsync {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $IsDirSynced = $Distgroup.IsDirSynced
    if ($IsDirSynced -eq $true) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because it's synchronized from on-premises!" -ForegroundColor Red
        "Distribution Group can't be upgraded because it's synchronized from on-premises!" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because EmailAddressPolicyViolated
Function Debugmatchingeap {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $eap = Get-EmailAddressPolicy -ErrorAction stop
    # Bypass that step if there's no EAP
    if ($null -ne $eap) {
        $matchingEap = @( $eap | Where-Object { $_.RecipientFilter -eq "RecipientTypeDetails -eq 'GroupMailbox'" -and $_.EnabledPrimarySMTPAddressTemplate.ToString().Split("@")[1] -cne $Distgroup.PrimarySmtpAddress.ToString().Split("@")[1] })
        if ($matchingEap.Count -ge 1) {
            $script:Conditionsfailed++
            Write-Host "Distribution Group can't be upgraded because Admin has applied Group Email Address Policy for the groups on the organization e.g. DL PrimarySmtpAddress @Contoso.com while the EAP EnabledPrimarySMTPAddressTemplate is @contoso.com OR DL PrimarySmtpAddress @contoso.com however there's an EAP with EnabledPrimarySMTPAddressTemplate set to @fabrikam.com" -ForegroundColor Red
            Write-Host "Group Email Address Policy found:" -BackgroundColor Yellow -ForegroundColor Black
            $matchingEap | Format-Table name, recipientfilter, Guid, enabledemailaddresstemplates
            "Distribution Group can't be upgraded because Admin has applied Group Email Address Policy for the groups on the organization e.g. DL PrimarySmtpAddress @Contoso.com while the EAP EnabledPrimarySMTPAddressTemplate is @contoso.com OR DL PrimarySmtpAddress @contoso.com however there's an EAP with EnabledPrimarySMTPAddressTemplate set to @fabrikam.com" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            "Group Email Address Policy found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $matchingEap | Format-Table name, recipientfilter, Guid, enabledemailaddresstemplates | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        }
    }
}
#Check if Distribution Group can't be upgraded because DlHasParentGroups
Function Debuggroupnesting {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $ParentDGroups = @()
    try {
        $alldgs = Get-DistributionGroup -ResultSize unlimited -ErrorAction Stop
        $CurrentDescription = "Retrieving All DGs in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve All DGs" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    } catch {
        $CurrentDescription = "Retrieving All DGs in the EXO directory"
        $CurrentStatus = "Failure"
        log -Function "Retrieve All DGs" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    }
    foreach ($parentdg in $alldgs) {
        try {
            $Pmembers = Get-DistributionGroupMember $($parentdg.Guid.ToString()) -ErrorAction Stop
        } catch {
            $CurrentDescription = "Retrieving: $parentdg members"
            $CurrentStatus = "Failure"
            log -Function "Retrieve Distribution Group membership" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
        }

        foreach ($member in $Pmembers) {
            if ($member.Guid.Guid.ToString() -like $Distgroup.Guid.Guid.ToString()) {
                $ParentDGroups += $parentdg
            }
        }
    }
    if ($ParentDGroups.Count -ge 1) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because it is a child group of another parent group" -ForegroundColor Red
        Write-Host "Parent Groups found:" -BackgroundColor Yellow -ForegroundColor Black
        $ParentDGroups | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because it is a child group of another parent group"  | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Parent Groups found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $ParentDGroups | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because DlHasNonSupportedMemberTypes with RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser
Function Debugmembersrecipienttypes {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )

    try {
        $members = Get-DistributionGroupMember $($Distgroup.Guid.ToString()) -ErrorAction stop
        $CurrentDescription = "Retrieving: $Distgroup.PrimarySmtpAddress members"
        $CurrentStatus = "Success"
        log -Function "Retrieve Distribution Group membership" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $CurrentDescription = "Retrieving: $Distgroup.PrimarySmtpAddress members"
        $CurrentStatus = "Failure"
        log -Function "Retrieve Distribution Group membership" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }
    $matchingMbr = @( $members | Where-Object { $_.RecipientTypeDetails -ne "UserMailbox" -and `
                $_.RecipientTypeDetails -ne "SharedMailbox" -and `
                $_.RecipientTypeDetails -ne "TeamMailbox" -and `
                $_.RecipientTypeDetails -ne "MailUser" -and `
                $_.RecipientTypeDetails -ne "GuestMailUser" -and `
                $_.RecipientTypeDetails -ne "RoomMailbox" -and `
                $_.RecipientTypeDetails -ne "EquipmentMailbox" -and `
                $_.RecipientTypeDetails -ne "User" -and `
                $_.RecipientTypeDetails -ne "DisabledUser" `
        })

    if ($matchingMbr.Count -ge 1) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because DL contains member RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser" -ForegroundColor Red
        Write-Host "Non-supported members found:" -BackgroundColor Yellow -ForegroundColor Black
        $matchingMbr | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because DL contains member RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Non-supported members found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $matchingMbr | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because it has more than 100 owners or it has no owner
Function Debugownerscount {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $owners = $Distgroup.ManagedBy
    if ($owners.Count -gt 100 -or $owners.Count -eq 0) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because it has more than 100 owners or it has no owners" -ForegroundColor Red
        "Distribution Group can't be upgraded because it has more than 100 owners or it has no owners" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because the distribution list owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser
Function Debugownersstatus {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $owners = $Distgroup.ManagedBy
    if ($owners.Count -le 100 -and $owners.Count -ge 1) {
        $ConditionDGownerswithoutMBX = @()
        foreach ($owner in $owners) {
            try {
                $owner = Get-Recipient $owner -ErrorAction stop
                $CurrentDescription = "Validating: $owner RecipientTypeDetails"
                $CurrentStatus = "Success"
                log -Function "Validate owner RecipientTypeDetails" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
                if (!($owner.RecipientTypeDetails -eq "UserMailbox" -or $owner.RecipientTypeDetails -eq "MailUser")) {
                    $ConditionDGownerswithoutMBX = $ConditionDGownerswithoutMBX + $owner
                }
            } catch {
                $CurrentDescription = "Validating: $owner RecipientTypeDetails"
                $CurrentStatus = "Failure"
                log -Function "Validate owner RecipientTypeDetails" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
                #Check if the owner RecipientTypeDetails is User
                $owner = Get-User $owner -ErrorAction stop
                $ConditionDGownerswithoutMBX = $ConditionDGownerswithoutMBX + $owner
            }
        }
        if ($ConditionDGownerswithoutMBX.Count -ge 1) {
            Write-Host "Distribution Group can't be upgraded because DL owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser" -ForegroundColor Red
            Write-Host "Non-supported Owner(s) found:" -BackgroundColor Yellow -ForegroundColor Black
            $ConditionDGownerswithoutMBX | Format-Table -AutoSize -Wrap Name, GUID, RecipientTypeDetails
            "Distribution Group can't be upgraded because DL owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            "Non-supported Owner(s) found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $ConditionDGownerswithoutMBX | Format-Table -AutoSize -Wrap Name, GUID, RecipientTypeDetails | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $script:Conditionsfailed++
        }
    }
}
#Check if Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL
Function Debugsenderrestriction {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $ConditionDGSender = @()
    [int]$SenderRestrictionCount = 0
    foreach ($alldg in $alldgs) {
        if ($alldg.AcceptMessagesOnlyFromSendersOrMembers -match $Distgroup.Name -or $alldg.AcceptMessagesOnlyFromDLMembers -match $Distgroup.Name ) {

            $ConditionDGSender = $ConditionDGSender + $alldg
            $SenderRestrictionCount++
        }
    }
    if ($SenderRestrictionCount -ge 1) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL" -ForegroundColor Red
        Write-Host "Distribution group(s) with sender restriction:" -BackgroundColor Yellow -ForegroundColor Black
        $ConditionDGSender | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Distribution group(s) with sender restriction:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $ConditionDGSender | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because Distribution lists which were converted to RoomLists or isn't a security group nor Dynamic DG
Function Debuggrouprecipienttype {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    if ($Distgroup.RecipientTypeDetails -like "MailUniversalSecurityGroup" -or $Distgroup.RecipientTypeDetails -like "DynamicDistributionGroup" -or $Distgroup.RecipientTypeDetails -like "roomlist" ) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because it was converted to RoomList or is found to be a security group or Dynamic distribution group" -ForegroundColor Red
        Write-Host "Distribution Group RecipientTypeDetails is: " $Distgroup.RecipientTypeDetails
        "Distribution Group can't be upgraded because it was converted to RoomList or is found to be a security group or Dynamic distribution group" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Distribution Group RecipientTypeDetails is: " + $Distgroup.RecipientTypeDetails | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox
Function Debugforwardingforsharedmbxs {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    $Conditionfwdmbx = @()
    try {
        $sharedMBXs = Get-Mailbox -ResultSize unlimited -RecipientTypeDetails sharedmailbox -ErrorAction stop
        $CurrentDescription = "Retrieving All Shared MBXs in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve Shared Mailboxes" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    } catch {
        $CurrentDescription = "Retrieving All Shared MBXs in the EXO directory"
        $CurrentStatus = "Failure"
        write-log -Function "Retrieve Shared Mailboxes" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    }
    $counter = 0
    foreach ($sharedMBX in $sharedMBXs) {
        if ($sharedMBX.ForwardingAddress -match $Distgroup.name -or $sharedMBX.ForwardingSmtpAddress -match $Distgroup.PrimarySmtpAddress) {
            $Conditionfwdmbx = $Conditionfwdmbx + $sharedMBX
            $counter++
        }
    }
    if ($counter -ge 1) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox" -ForegroundColor Red
        Write-Host "Shared Mailbox(es):" -BackgroundColor Yellow -ForegroundColor Black
        $Conditionfwdmbx | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Shared Mailbox(es):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $Conditionfwdmbx | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check for duplicate Alias,PrimarySmtpAddress,Name,DisplayName on EXO objects
Function Debugduplicateobjects {
    param(
        [Parameter(Mandatory = $true)]
        [PScustomobject]$Distgroup
    )
    try {
        $dupAlias = Get-Recipient -IncludeSoftDeletedRecipients -Identity $Distgroup.alias -ResultSize unlimited -ErrorAction stop
        $dupAddress = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $Distgroup.PrimarySmtpAddress -ErrorAction stop
        $dupDisplayName = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $Distgroup.DisplayName -ErrorAction stop
        $dupName = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $Distgroup.Name -ErrorAction stop
        $CurrentDescription = "Retrieving duplicate recipients having same Alias,PrimarySmtpAddress,Name,DisplayName in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve Duplicate Recipient Objects" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $CurrentDescription = "Retrieving duplicate recipients having same Alias,PrimarySmtpAddress,Name,DisplayName in the EXO directory"
        $CurrentStatus = "Failure"
        log -Function "Retrieve Duplicate Recipient Objects" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }

    if ($dupAlias.Count -ge 2) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same Alias found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupalias | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same Alias found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupalias | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupAddress.Count -ge 2) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same PrimarySmtpAddress found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupAddress | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same PrimarySmtpAddress found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupAddress | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress   | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupDisplayName.Count -ge 2) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same DisplayName found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupDisplayName | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same DisplayName found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupDisplayName | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupName.Count -ge 2) {
        $script:Conditionsfailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same Name found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupName | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same Name found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupName | Where-Object { $_.guid -notlike $Distgroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}

#Connect to EXO PS
$Sessioncheck = Get-PSSession | Where-Object { $_.Name -like "*Exchangeonline*" -and $_.State -match "opened" }
if ($null -eq $Sessioncheck) {
    #Collect Admin credentials
    $UserCredential = Get-Credential -Message "Please enter global admin Username\password to connect to Exchange online"
    Connect2EXO($UserCredential)
}

#Getting the DG SMTP
$dgsmtp = Read-Host "Please enter email address of the Distribution Group"
$dgsmtp = $dgsmtp.ToLower().ToString()
try {
    $dg = get-DistributionGroup -Identity $dgsmtp -ErrorAction stop
    $CurrentDescription = "Retrieving Distribution Group from EXO Directory"
    $CurrentStatus = "Success"
    log -CurrentStatus $CurrentStatus -Function "Retrieving Distribution Group from EXO Directory" -CurrentDescription $CurrentDescription
} catch {
    $CurrentDescription = "Retrieving Distribution Group from EXO Directory"
    $CurrentStatus = "Failure"
    log -CurrentStatus $CurrentStatus -Function "Retrieving Distribution Group from EXO Directory" -CurrentDescription $CurrentDescription
    Write-Host "You entered an incorrect smtp, the script is quitting!" -ForegroundColor Red
    Break
}


#Intro with group name
[String]$article = "https://docs.microsoft.com/en-us/microsoft-365/admin/manage/upgrade-distribution-lists?view=o365-worldwide"
[string]$Description = "This script illustrates Distribution to O365 Group migration eligibility checks taken place over group SMTP: " + $dgsmtp + ", migration BLOCKERS will be reported down!,please ensure to mitigate them"
$Description = $Description + ",for more informtion please check: $article`n"
Write-Host $Description -ForegroundColor Cyan
$Description | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append


#Main Function

DebugMemberRestriction($dg)
DebugDirSync($dg)
Debugmatchingeap($dg)
Debuggroupnesting($dg)
DebugmembersrecipientTypes($dg)
Debugownerscount($dg)
Debugownersstatus($dg)
Debugsenderrestriction($dg)
Debuggrouprecipienttype($dg)
Debugforwardingforsharedmbxs($dg)
Debugduplicateobjects($dg)

if ($Conditionsfailed -eq 0) {
    Write-Host "All checks passed please proceed to upgrade the distribution group" -ForegroundColor Green
    "All checks passed please proceed to upgrade the distribution group" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
}

# End of the Diag
Write-Host "`nlog file was exported in the following location: $ExportPath" -ForegroundColor Yellow
Start-Sleep -Seconds 3
