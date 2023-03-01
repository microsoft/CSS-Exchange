# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Do not want to change logic of script as of now')]
[CmdletBinding()]
param()

#Create working folder on the logged user desktop
$ts = Get-Date -Format yyyyMMdd_HHmmss
$ExportPath = "$env:USERPROFILE\Desktop\PowershellDGUpgrade\DlToO365GroupUpgradeChecks_$ts"
mkdir $ExportPath -Force | Out-Null
Add-Content -Path $ExportPath\DlToO365GroupUpgradeChecksLogging.csv  -Value '"Function","Description","Status"'
$Script:ConditionsFailed = 0
function log {
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
    $PSobject | Export-Csv $ExportPath\DlToO365GroupUpgradeChecksLogging.csv -NoTypeInformation -Append
}
function Connect2EXO {
    try {
        #Validate EXO V2 is installed
        if ((Get-Module | Where-Object { $_.Name -like "ExchangeOnlineManagement" }).count -eq 1) {
            Import-Module ExchangeOnlineManagement -ErrorAction stop -Force
            $CurrentDescription = "Importing EXO V2 Module"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Importing EXO V2 Module" -CurrentDescription $CurrentDescription
            Write-Warning "Connecting to EXO V2, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
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
            Write-Warning "Connecting to EXO V2, please enter Global administrator credentials when prompted!"
            Connect-ExchangeOnline -ErrorAction Stop
            $CurrentDescription = "Connecting to EXO V2"
            $CurrentStatus = "Success"
            log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
            Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
        }
    } catch {
        $CurrentDescription = "Connecting to EXO V2 please check if ExchangeOnlineManagement Powershell Module is installed & imported"
        $CurrentStatus = "Failure"
        log -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        break
    }
}
#Check if Distribution Group can't be upgraded because Member*Restriction is set to "Closed"
function DebugMemberRestriction {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup

    )
    $MemberJoinRestriction = $DistGroup.MemberJoinRestriction.ToLower().ToString()
    $MemberDepartRestriction = $DistGroup.MemberDepartRestriction.ToLower().ToString()
    if ($MemberDepartRestriction -eq "closed" -or $MemberJoinRestriction -eq "closed") {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded cause either MemberJoinRestriction or MemberDepartRestriction or both values are set to Closed!" -ForegroundColor Red
        "Distribution Group can't be upgraded cause either MemberJoinRestriction or MemberDepartRestriction or both values are set to Closed!" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with fixing DL Member*Restriction & set DL MemberJoin/DepartRestriction to Open!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with fixing DL Member*Restriction & set DL MemberJoin/DepartRestriction to Open!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because it is DirSynced
function DebugDirSync {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $IsDirSynced = $DistGroup.IsDirSynced
    if ($IsDirSynced -eq $true) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because it's synchronized from on-premises!`n" -ForegroundColor Red
        "Distribution Group can't be upgraded because it's synchronized from on-premises!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because EmailAddressPolicyViolated
function DebugMatchingEap {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $eap = Get-EmailAddressPolicy -ErrorAction stop
    # Bypass that step if there's no EAP
    if ($null -ne $eap) {
        $matchingEap = @( $eap | Where-Object { $_.RecipientFilter -eq "RecipientTypeDetails -eq 'GroupMailbox'" -and $_.EnabledPrimarySMTPAddressTemplate.ToString().Split("@")[1] -cne $DistGroup.PrimarySmtpAddress.ToString().Split("@")[1] })
        if ($matchingEap.Count -ge 1) {
            $script:ConditionsFailed++
            Write-Host "Distribution Group can't be upgraded because Admin has applied Group Email Address Policy for the groups on the organization e.g. DL PrimarySmtpAddress @Contoso.com while the EAP EnabledPrimarySMTPAddressTemplate is @contoso.com OR DL PrimarySmtpAddress @contoso.com however there's an EAP with EnabledPrimarySMTPAddressTemplate set to @fabrikam.com" -ForegroundColor Red
            Write-Host "Group Email Address Policy found:" -BackgroundColor Yellow -ForegroundColor Black
            $matchingEap | Format-Table name, RecipientFilter, Guid, EnabledEmailAddressTemplates
            "Distribution Group can't be upgraded because Admin has applied Group Email Address Policy for the groups on the organization e.g. DL PrimarySmtpAddress @Contoso.com while the EAP EnabledPrimarySMTPAddressTemplate is @contoso.com OR DL PrimarySmtpAddress @contoso.com however there's an EAP with EnabledPrimarySMTPAddressTemplate set to @fabrikam.com" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            "Group Email Address Policy found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $matchingEap | Format-Table name, RecipientFilter, Guid, EnabledEmailAddressTemplates | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            Write-Host "FIX --> Please follow the following article https://aka.ms/removeeap to proceed with removing non-matching EmailAddressPolicy!`n" -ForegroundColor Green
            "FIX --> Please follow the following article https://aka.ms/removeeap to proceed with removing non-matching EmailAddressPolicy!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        }
    }
}
#Check if Distribution Group can't be upgraded because DlHasParentGroups
function DebugGroupNesting {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $ParentDGroups = @()
    try {
        Write-Warning "Retrieving all distribution groups in Exchange online to validate Dl for nested Dl condition, please wait...."
        $allDgs = Get-DistributionGroup -ResultSize unlimited -ErrorAction Stop
        $CurrentDescription = "Retrieving All DGs in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve All DGs" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    } catch {
        $CurrentDescription = "Retrieving All DGs in the EXO directory"
        $CurrentStatus = "Failure"
        log -Function "Retrieve All DGs" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    }
    $DGcounter=0
    foreach ($parentDg in $allDgs) {
        try {
            $pMembers = Get-DistributionGroupMember $($parentDg.Guid.ToString()) -ErrorAction Stop
            if ($allDgs.count -ge 2) {
                $DGcounter++
                $percent=[Int32]($DGcounter/$allDgs.count*100)
                Write-Progress -Activity "Querying Distribution Groups"  -PercentComplete $percent -Status "Processing $DGcounter/$($allDgs.count)group"
            }
        } catch {
            $CurrentDescription = "Retrieving: $parentDg members"
            $CurrentStatus = "Failure"
            log -Function "Retrieve Distribution Group membership" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
        }
        $DgMemberCounter=0
        foreach ($member in $pMembers) {
            if ($member.Guid.Guid.ToString() -like $DistGroup.Guid.Guid.ToString()) {
                $ParentDGroups += $parentDg
            }
            if ($pMembers.count -ge 2) {
                $DgMemberCounter++
                $childPercent=[Int32]($DgMemberCounter/$pMembers.count*100)
                Write-Progress -Activity "Querying Group Members" -Id 1 -PercentComplete $childPercent -Status "Processing $DgMemberCounter/$($pMembers.count) member"
            }
        }
    }
    Write-Progress -Activity "Querying Group Members" -Completed -Id 1
    Write-Progress -Activity "Querying Distribution Groups" -Completed
    if ($ParentDGroups.Count -ge 1) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because it is a child group of another parent group" -ForegroundColor Red
        Write-Host "Parent Groups found:" -BackgroundColor Yellow -ForegroundColor Black
        $ParentDGroups | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because it is a child group of another parent group"  | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Parent Groups found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $ParentDGroups | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/RemoveDGmember to proceed with removing DL membership from Parent DL(s)!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/RemoveDGmember to proceed with removing DL membership from Parent DL(s)!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because DlHasNonSupportedMemberTypes with RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser
function DebugMembersRecipientTypes {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )

    try {
        Write-Warning "Retrieving $($DistGroup.PrimarySmtpAddress) group members to validate DlHasNonSupportedMemberTypes condition, please wait...."
        $members = Get-DistributionGroupMember $($DistGroup.Guid.ToString()) -ErrorAction stop
        $CurrentDescription = "Retrieving: $($DistGroup.PrimarySmtpAddress) members"
        $CurrentStatus = "Success"
        log -Function "Retrieve Distribution Group membership" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $CurrentDescription = "Retrieving: $($DistGroup.PrimarySmtpAddress) members"
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
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because DL contains member RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser" -ForegroundColor Red
        Write-Host "Non-supported members found:" -BackgroundColor Yellow -ForegroundColor Black
        $matchingMbr | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because DL contains member RecipientTypeDetails other than UserMailbox, SharedMailbox, TeamMailbox, MailUser" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Non-supported members found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $matchingMbr | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/RemoveDGmember to proceed with removing NonSupportedMemberTypes membership from the DL!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/RemoveDGmember to proceed with removing NonSupportedMemberTypes membership from the DL!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because it has more than 100 owners or it has no owner
function DebugOwnersCount {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $owners = $DistGroup.ManagedBy
    if ($owners.Count -gt 100 -or $owners.Count -eq 0) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because it has more than 100 owners or it has no owners" -ForegroundColor Red
        "Distribution Group can't be upgraded because it has more than 100 owners or it has no owners" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to adjust owners(ManagedBy) count!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to adjust owners(ManagedBy) count!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because the distribution list owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser
function DebugOwnersStatus {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $owners = $DistGroup.ManagedBy
    if ($owners.Count -le 100 -and $owners.Count -ge 1) {
        $ConditionDgOwnersWithoutMBX = @()
        foreach ($owner in $owners) {
            try {
                $owner = Get-Recipient $owner -ErrorAction stop
                $CurrentDescription = "Validating: $owner RecipientTypeDetails"
                $CurrentStatus = "Success"
                log -Function "Validate owner RecipientTypeDetails" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
                if (!($owner.RecipientTypeDetails -eq "UserMailbox" -or $owner.RecipientTypeDetails -eq "MailUser")) {
                    $ConditionDgOwnersWithoutMBX = $ConditionDgOwnersWithoutMBX + $owner
                }
            } catch {
                $CurrentDescription = "Validating: $owner RecipientTypeDetails"
                $CurrentStatus = "Failure"
                log -Function "Validate owner RecipientTypeDetails" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
                #Check if the owner RecipientTypeDetails is User
                $owner = Get-User $owner -ErrorAction stop
                $ConditionDgOwnersWithoutMBX = $ConditionDgOwnersWithoutMBX + $owner
            }
        }
        if ($ConditionDgOwnersWithoutMBX.Count -ge 1) {
            Write-Host "Distribution Group can't be upgraded because DL owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser" -ForegroundColor Red
            Write-Host "Non-supported Owner(s) found:" -BackgroundColor Yellow -ForegroundColor Black
            $ConditionDgOwnersWithoutMBX | Format-Table -AutoSize -Wrap Name, GUID, RecipientTypeDetails
            "Distribution Group can't be upgraded because DL owner(s) is non-supported with RecipientTypeDetails other than UserMailbox, MailUser" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            "Non-supported Owner(s) found:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $ConditionDgOwnersWithoutMBX | Format-Table -AutoSize -Wrap Name, GUID, RecipientTypeDetails | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            $script:ConditionsFailed++
            #fix will occur if we still have supported owners to avoid zero owner condition
            if ($owners.Count -gt $ConditionDgOwnersWithoutMBX.Count) {
                Write-Host "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with removing non-supported RecipientTypeDetails owner(ManagedBy)!`n" -ForegroundColor Green
                "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with removing non-supported RecipientTypeDetails owner(ManagedBy)!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
            }
        }
    }
}
#Check if Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL
function DebugSenderRestriction {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $ConditionDGSender = @()
    $DgCounterLoop=0
    [int]$SenderRestrictionCount = 0
    foreach ($allDg in $allDgs) {
        if ($allDgs.count -ge 2) {
            $DgCounterLoop++
            $percent=[Int32]($DgCounterLoop/$allDgs.count*100)
            Write-Progress -Activity "Validating Distribution Groups Sender Restriction"  -PercentComplete $percent -Status "Processing $DgCounterLoop/$($allDgs.count)group"
        }
        if ($allDg.AcceptMessagesOnlyFromSendersOrMembers -match $DistGroup.Name -or $allDg.AcceptMessagesOnlyFromDLMembers -match $DistGroup.Name ) {

            $ConditionDGSender = $ConditionDGSender + $allDg
            $SenderRestrictionCount++
        }
    }
    Write-Progress -Activity "Validating Distribution Groups Sender Restriction" -Completed
    if ($SenderRestrictionCount -ge 1) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL" -ForegroundColor Red
        Write-Host "Distribution group(s) with sender restriction:" -BackgroundColor Yellow -ForegroundColor Black
        $ConditionDGSender | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because the distribution list is part of Sender Restriction in another DL" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Distribution group(s) with sender restriction:" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $ConditionDGSender | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with removing DL from AcceptMessagesOnlyFromSendersOrMembers/AcceptMessagesOnlyFromDLMembers restriction in another DL(s)!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/Setdistributiongroup to proceed with removing DL from AcceptMessagesOnlyFromSendersOrMembers/AcceptMessagesOnlyFromDLMembers restriction in another DL(s)!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because Distribution lists which were converted to RoomLists or isn't a security group nor Dynamic DG
function DebugGroupRecipientType {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    if ($DistGroup.RecipientTypeDetails -like "MailUniversalSecurityGroup" -or $DistGroup.RecipientTypeDetails -like "DynamicDistributionGroup" -or $DistGroup.RecipientTypeDetails -like "RoomList" ) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because it was converted to RoomList or is found to be a security group or Dynamic distribution group" -ForegroundColor Red
        Write-Host "Distribution Group RecipientTypeDetails is: " $DistGroup.RecipientTypeDetails
        "Distribution Group can't be upgraded because it was converted to RoomList or is found to be a security group or Dynamic distribution group" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Distribution Group RecipientTypeDetails is: " + $DistGroup.RecipientTypeDetails | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check if Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox
function DebugForwardingForSharedMbxs {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    $ConditionFwdMbx = @()
    try {
        Write-Warning "Retrieving all shared mailboxes in Exchange online to validate if Dl is configured as a forwarding address for a Shared Mailbox, please wait...."
        $sharedMBXs = Get-Mailbox -ResultSize unlimited -RecipientTypeDetails sharedMailbox -ErrorAction stop
        $CurrentDescription = "Retrieving All Shared MBXs in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve Shared Mailboxes" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    } catch {
        $CurrentDescription = "Retrieving All Shared MBXs in the EXO directory"
        $CurrentStatus = "Failure"
        write-log -Function "Retrieve Shared Mailboxes" -CurrentDescription $CurrentDescription -CurrentStatus $CurrentStatus
    }
    $counter = 0
    $SharedCounter=0
    foreach ($sharedMBX in $sharedMBXs) {
        if ($sharedMBX.ForwardingAddress -match $DistGroup.name -or $sharedMBX.ForwardingSmtpAddress -match $DistGroup.PrimarySmtpAddress) {
            $ConditionFwdMbx = $ConditionFwdMbx + $sharedMBX
            $counter++
            $percent=[Int32]($SharedCounter/$sharedMBXs.count*100)
            Write-Progress -Activity "Querying Shared Mailboxes"  -PercentComplete $percent -Status "Processing $SharedCounter/$($sharedMBXs.count) Mailboxes"
        }
    }
    Write-Progress -Activity "Querying Shared Mailboxes" -Completed
    if ($counter -ge 1) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox" -ForegroundColor Red
        Write-Host "Shared Mailbox(es):" -BackgroundColor Yellow -ForegroundColor Black
        $ConditionFwdMbx | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because the distribution list is configured to be a forwarding address for Shared Mailbox" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Shared Mailbox(es):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $ConditionFwdMbx | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        Write-Host "FIX --> Please follow the following article https://aka.ms/Setmailbox to proceed with removing DL from ForwardingAddress/ForwardingSmtpAddress in shared mailbox(es)!`n" -ForegroundColor Green
        "FIX --> Please follow the following article https://aka.ms/Setmailbox to proceed with removing DL from ForwardingAddress/ForwardingSmtpAddress in shared mailbox(es)!`n" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}
#Check for duplicate Alias,PrimarySmtpAddress,Name,DisplayName on EXO objects
function DebugDuplicateObjects {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DistGroup
    )
    try {
        Write-Warning "Querying across Exchange online recipients for duplicate objects with $($DistGroup.PrimarySmtpAddress) group, please wait..."
        $dupAlias = Get-Recipient -IncludeSoftDeletedRecipients -Identity $DistGroup.alias -ResultSize unlimited -ErrorAction stop
        $dupAddress = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $DistGroup.PrimarySmtpAddress -ErrorAction stop
        $dupDisplayName = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $DistGroup.DisplayName -ErrorAction stop
        $dupName = Get-Recipient -IncludeSoftDeletedRecipients -ResultSize unlimited -Identity $DistGroup.Name -ErrorAction stop
        $CurrentDescription = "Retrieving duplicate recipients having same Alias,PrimarySmtpAddress,Name,DisplayName in the EXO directory"
        $CurrentStatus = "Success"
        log -Function "Retrieve Duplicate Recipient Objects" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $CurrentDescription = "Retrieving duplicate recipients having same Alias,PrimarySmtpAddress,Name,DisplayName in the EXO directory"
        $CurrentStatus = "Failure"
        log -Function "Retrieve Duplicate Recipient Objects" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }

    if ($dupAlias.Count -ge 2) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same Alias found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupAlias | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same Alias found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupAlias | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupAddress.Count -ge 2) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same PrimarySmtpAddress found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupAddress | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same PrimarySmtpAddress found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupAddress | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress   | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupDisplayName.Count -ge 2) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same DisplayName found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupDisplayName | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same DisplayName found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupDisplayName | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    } elseif ($dupName.Count -ge 2) {
        $script:ConditionsFailed++
        Write-Host "Distribution Group can't be upgraded because duplicate objects having same Name found" -ForegroundColor Red
        Write-Host "Duplicate account(s):" -BackgroundColor Yellow -ForegroundColor Black
        $dupName | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress
        "Distribution Group can't be upgraded because duplicate objects having same Name found" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        "Duplicate account(s):" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
        $dupName | Where-Object { $_.guid -notlike $DistGroup.guid } | Format-Table -AutoSize DisplayName, Alias, GUID, RecipientTypeDetails, PrimarySmtpAddress | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
    }
}

#Connect to EXO PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*ExchangeOnline*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect2EXO
}

#Getting the DG SMTP
$dgSmtp = Read-Host "Please enter email address of the Distribution Group"
$dgSmtp = $dgSmtp.ToLower().ToString()
try {
    $dg = get-DistributionGroup -Identity $dgSmtp -ErrorAction stop
    $CurrentDescription = "Retrieving Distribution Group from EXO Directory"
    $CurrentStatus = "Success"
    log -CurrentStatus $CurrentStatus -Function "Retrieving Distribution Group from EXO Directory" -CurrentDescription $CurrentDescription
} catch {
    $CurrentDescription = "Retrieving Distribution Group from EXO Directory"
    $CurrentStatus = "Failure"
    log -CurrentStatus $CurrentStatus -Function "Retrieving Distribution Group from EXO Directory" -CurrentDescription $CurrentDescription
    Write-Host "You entered an incorrect smtp, the script is quitting!`n" -ForegroundColor Red
    break
}

#Intro with group name
[String]$article = "https://aka.ms/DlToM365GroupUpgrade"
[string]$Description = "This script illustrates Distribution to O365 Group migration eligibility checks taken place over group SMTP: " + $dgSmtp + ", migration BLOCKERS will be reported down!`n,please ensure to mitigate them"
$Description = $Description + ",for more information please check: $article`n"
Write-Host $Description -ForegroundColor Cyan
$Description | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append

#Main Function
DebugMemberRestriction($dg)
DebugDirSync($dg)
DebugMatchingEap($dg)
DebugGroupNesting($dg)
DebugMembersRecipientTypes($dg)
DebugOwnersCount($dg)
DebugOwnersStatus($dg)
DebugSenderRestriction($dg)
DebugGroupRecipientType($dg)
DebugForwardingForSharedMbxs($dg)
DebugDuplicateObjects($dg)

if ($ConditionsFailed -eq 0) {
    Write-Host "All checks passed please proceed to upgrade the distribution group" -ForegroundColor Green
    "All checks passed please proceed to upgrade the distribution group" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append
}
#Ask for feedback
Write-Host "Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/DTGFeedback!" -ForegroundColor Cyan
"Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/DTGFeedback!" | Out-File $ExportPath\DlToO365GroupUpgradeChecksREPORT.txt -Append

# End of the Diag
Write-Host "`nLog file was exported in the following location: $ExportPath" -ForegroundColor Yellow
Start-Sleep -Seconds 3
