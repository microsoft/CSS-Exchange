# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# .DESCRIPTION
# This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear english,
# highlighting the key settings that affect RBA and some of the common errors in configuration.
#
# .PARAMETER Identity
# Address of Resource Mailbox to query
#
# .PARAMETER IncludeSensitiveData
# Includes full-fidelity identities, RBA log content, and transcript content in the JSON output.
#
# .PARAMETER MeetingSubject
# Searches the retained RBA diagnostic log for this subject, extracts meeting IDs from matching processing blocks,
# and includes every retained RBA processing block for those meeting IDs in the JSON output.
#
# .PARAMETER SkipVersionCheck
# Skips the automatic script update check.
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com
# or
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Verbose

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Identity,

    [ValidateNotNullOrEmpty()]
    [string]$MeetingSubject,

    [switch]$IncludeSensitiveData,

    [switch]$SkipVersionCheck
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (-not $SkipVersionCheck -and (Test-ScriptVersion -AutoUpdate)) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

$runTimestamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
$SummaryFilename = "RBA-Summary-For_$($Identity.Split('@')[0])_$runTimestamp.txt"
$JsonFilename = "RBA-Summary-For_$($Identity.Split('@')[0])_$runTimestamp.json"
$script:collectorStatuses = [ordered]@{}
$script:collectionErrors = [System.Collections.Generic.List[object]]::new()
$script:evaluationErrors = [System.Collections.Generic.List[object]]::new()
$script:TranscriptStarted = $false
$script:ResourceDelegateIdentitySets = @()
$script:ResourceDelegateIdentitySetsAvailable = $false
$script:SanitizedIdentityMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:SanitizedIdentitySequence = 0
Write-Host "`r`nRBA Summary Output saved as [" -NoNewline
Write-Host -ForegroundColor Cyan $SummaryFilename -NoNewline
Write-Host "] in the current directory."
try {
    Start-Transcript -Path $SummaryFilename -ErrorAction Stop | Out-Null
    $script:TranscriptStarted = $true
} catch {
    Write-Warning "Unable to start transcript '$SummaryFilename': $($_.Exception.Message)"
}
Write-Host "`r`n"

function ConvertTo-RbaSafeErrorText {
    param(
        [AllowNull()]
        [object]$Value,

        [int]$MaximumLength = 2048
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        $text = [string]$Value
    } catch {
        return $null
    }

    $text = ($text -replace '[\r\n\t]+', ' ').Trim()
    if ($text.Length -gt $MaximumLength) {
        return $text.Substring(0, $MaximumLength)
    }
    return $text
}

function ConvertTo-RbaErrorInfo {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    $exception = $null
    if ($ErrorRecord -is [System.Exception]) {
        $exception = $ErrorRecord
    } elseif ($null -ne $ErrorRecord) {
        try {
            $exception = $ErrorRecord.PSObject.Properties['Exception'].Value
        } catch {
            $exception = $null
        }
    }

    $message = $null
    $exceptionType = $null
    $innerExceptionMessage = $null
    if ($null -ne $exception) {
        try {
            $message = ConvertTo-RbaSafeErrorText -Value $exception.Message
        } catch {
            $message = $null
        }
        try {
            $exceptionType = ConvertTo-RbaSafeErrorText -Value $exception.GetType().FullName -MaximumLength 256
        } catch {
            $exceptionType = $null
        }
        try {
            $innerExceptionMessage = ConvertTo-RbaSafeErrorText -Value $exception.InnerException.Message -MaximumLength 1024
        } catch {
            $innerExceptionMessage = $null
        }
    }
    if ([string]::IsNullOrEmpty($message) -and $ErrorRecord -is [string]) {
        $message = ConvertTo-RbaSafeErrorText -Value $ErrorRecord
    }
    if ([string]::IsNullOrEmpty($message)) {
        $message = "Unknown error."
    }

    $category = $null
    $fullyQualifiedErrorId = $null
    if ($null -ne $ErrorRecord) {
        try {
            $category = ConvertTo-RbaSafeErrorText -Value $ErrorRecord.PSObject.Properties['CategoryInfo'].Value.Category -MaximumLength 256
        } catch {
            $category = $null
        }
        try {
            $fullyQualifiedErrorId = ConvertTo-RbaSafeErrorText -Value $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId'].Value -MaximumLength 256
        } catch {
            $fullyQualifiedErrorId = $null
        }
    }

    return [PSCustomObject]@{
        message               = $message
        exceptionType         = $exceptionType
        category              = $category
        fullyQualifiedErrorId = $fullyQualifiedErrorId
        innerExceptionMessage = $innerExceptionMessage
    }
}

function Invoke-RbaCollector {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action,

        [switch]$AllowEmptyCollection
    )

    try {
        $result = & $Action
        if ($null -eq $result -and -not $AllowEmptyCollection) {
            throw "$Name returned null."
        }
        $script:collectorStatuses[$Name] = [PSCustomObject]@{
            status                = "Success"
            error                 = $null
            exceptionType         = $null
            category              = $null
            fullyQualifiedErrorId = $null
            innerExceptionMessage = $null
        }
        return $result
    } catch {
        $errorInfo = ConvertTo-RbaErrorInfo -ErrorRecord $_
        $script:collectorStatuses[$Name] = [PSCustomObject]@{
            status                = "Failed"
            error                 = $errorInfo.message
            exceptionType         = $errorInfo.exceptionType
            category              = $errorInfo.category
            fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
            innerExceptionMessage = $errorInfo.innerExceptionMessage
        }
        $script:collectionErrors.Add([PSCustomObject]@{
                collector             = $Name
                message               = $errorInfo.message
                exceptionType         = $errorInfo.exceptionType
                category              = $errorInfo.category
                fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
                innerExceptionMessage = $errorInfo.innerExceptionMessage
            })
        Write-Warning "$Name collection failed: $($errorInfo.message)"
        return $null
    }
}

function CollectMailbox {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-Mailbox -Identity $Identity"
    $script:Mailbox = Invoke-RbaCollector -Name "Mailbox" -Action {
        try {
            $mailbox = Get-Mailbox -Identity $Identity -ErrorAction Stop
            if ($null -eq $mailbox) {
                throw "Active mailbox lookup returned null."
            }
            $script:MailboxObjectState = "Active"
            return $mailbox
        } catch {
            Write-Verbose "Active mailbox lookup failed. Checking for a recoverable soft-deleted mailbox."
            $mailbox = Get-Mailbox -Identity $Identity -SoftDeletedMailbox -ErrorAction Stop
            if ($null -eq $mailbox) {
                throw "Soft-deleted mailbox lookup returned null."
            }
            $script:MailboxObjectState = "SoftDeleted"
            return $mailbox
        }
    }

    # check we get a response
    if ($null -eq $script:Mailbox) {
        Write-Host -ForegroundColor Red "Get-Mailbox was unavailable. Make sure you Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline. Continuing with other collectors."
    } else {
        if ($script:MailboxObjectState -eq "SoftDeleted") {
            Write-Host -ForegroundColor Red "The resource mailbox is soft-deleted and cannot perform active RBA processing."
        } elseif ($script:Mailbox.RecipientTypeDetails -ne "RoomMailbox" -and $script:Mailbox.RecipientTypeDetails -ne "EquipmentMailbox") {
            Write-Host -ForegroundColor Red "The mailbox is not a Room Mailbox / Equipment Mailbox. RBA will only work with these. Continuing collection."
        }
        if ($script:Mailbox.ResourceType -eq "Workspace") {
            $script:Workspace = $true
        }
        if ($script:Mailbox.RecipientTypeDetails -eq "RoomMailbox" -or $script:Mailbox.RecipientTypeDetails -eq "EquipmentMailbox") {
            Write-Host -ForegroundColor Green "The mailbox is valid for RBA to work with."
        }
    }
}

function CollectPlace {
    # Get-Place does not cross forest boundaries so we will get an error here if we are not in the right forest.
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-Place -Identity $Identity"
    $script:Place = Invoke-RbaCollector -Name "Place" -Action {
        Get-Place -Identity $Identity -ErrorAction Stop
    }

    if ($null -eq $script:Place) {
        Write-Host -ForegroundColor Red "Get-Place information is unavailable for $Identity."
        Write-Host -ForegroundColor Red "Make sure you are running from the correct forest.  Get-Place does not cross forest boundaries."
        if ($null -ne $script:Mailbox -and $null -ne $script:Mailbox.Database) {
            Write-Host "Hint Forest is likely something like: [$($script:Mailbox.Database.split("DG")[0])]."
        }
    }

    Write-Host -ForegroundColor Yellow "For more information see https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps"
    Write-Host
}

# Validate that there are not delegate rules that will block RBA functionality
function ValidateInboxRules {
    Write-Host "Checking for Delegate Rules that will block RBA functionality..."
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-InboxRule -mailbox $Identity -IncludeHidden"
    [array]$script:InboxRules = Invoke-RbaCollector -Name "InboxRules" -AllowEmptyCollection -Action {
        @(Get-InboxRule -Mailbox $Identity -IncludeHidden -ErrorAction Stop)
    }
    if ($script:collectorStatuses["InboxRules"].status -ne "Success") {
        Write-Host -ForegroundColor Yellow "Delegate Rules could not be evaluated because inbox rules are unavailable."
        return
    }
    [array]$rules = $script:InboxRules
    # Note as far as I can tell "Delegate Rule <GUID>" is not localized.
    if ($rules.Name -like "Delegate Rule*") {
        Write-Host -ForegroundColor Red "Error: There is a user style Delegate Rule setup on this resource mailbox. This will block RBA functionality. Please remove the rule via Remove-InboxRule cmdlet and re-run this script."
        Write-Host -NoNewline "Rule to look into: "
        Write-Host -ForegroundColor Red "$($rules.Name -like "Delegate Rule*")"
        Write-Host -ForegroundColor Red "Continuing collection so all available evidence is captured."
    } elseif ($rules.Name -like "REDACTED-*") {
        Write-Host -ForegroundColor Yellow "Warning: No PII Access to MB so cannot check for Delegate Rules."
        Write-Host -ForegroundColor Yellow "To gain PII access, Mailbox is located on $($mailbox.Database) on server $($mailbox.ServerName)"
        if ($null -eq $rules.count -or $rules.count -eq 1) {
            Write-Host -ForegroundColor Yellow "Warning: One rule has been found, which is likely the default Junk Mail rule."
            Write-Host -ForegroundColor Yellow "Warning: You should verify that this is not a Delegate Rule setup on this resource mailbox. Delegate rules will block RBA functionality. Please remove the rule via Remove-InboxRule cmdlet and re-run this script."
        } elseif ($rules.count -gt 1) {
            Write-Host -ForegroundColor Red " --- Inbox Rules needs to be checked manually for any Delegate Rules. --"
            Write-Host -ForegroundColor Red "Warning: Multiple rules have been found on this resource mailbox. Only the Default Junk Mail rule is expected.  Depending on the rules setup, this may block RBA functionality."
            Write-Host -ForegroundColor Red "Warning: Please remove the rule(s) via Remove-InboxRule cmdlet and re-run this script."
        }
    } else {
        Write-Host -ForegroundColor Green "Delegate Rules check passes."
    }
}

# Retrieve the CalendarProcessing information
function GetCalendarProcessing {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-CalendarProcessing -Identity $Identity"
    $script:RbaSettings = Invoke-RbaCollector -Name "CalendarProcessing" -Action {
        Get-CalendarProcessing -Identity $Identity -ErrorAction Stop
    }

    # check we get a response
    if ($null -eq $RbaSettings) {
        Write-Host -ForegroundColor Red "Get-CalendarProcessing returned null.
                Make sure you Import-Module ExchangeOnlineManagement
                and  Connect-ExchangeOnline
            Continuing with other available evidence."
        return
    }

    $RbaSettings | Format-List

    Write-Host -ForegroundColor Yellow "For more information on Set-CalendarProcessing see
                https://learn.microsoft.com/en-us/powershell/module/exchange/set-calendarprocessing?view=exchange-ps"
    Write-Host
}

function Get-RbaPermissionIdentity {
    param(
        [AllowNull()]
        [object]$PermissionUser
    )

    foreach ($propertyPath in @(
            @("ADRecipient", "PrimarySmtpAddress"),
            @("RecipientPrincipal", "PrimarySmtpAddress"),
            @("PrimarySmtpAddress")
        )) {
        try {
            $value = $PermissionUser
            foreach ($propertyName in $propertyPath) {
                $value = $value.PSObject.Properties[$propertyName].Value
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                return ([string]$value).ToLowerInvariant()
            }
        } catch {
            continue
        }
    }

    return ([string]$PermissionUser).ToLowerInvariant()
}

function CollectCalendarFolderPermissions {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-MailboxFolderPermission for the Calendar folder of $Identity"
    [array]$script:CalendarFolderPermissions = Invoke-RbaCollector -Name "CalendarFolderPermissions" -AllowEmptyCollection -Action {
        $calendarFolder = Get-MailboxFolderStatistics -Identity $Identity -FolderScope Calendar -ErrorAction Stop |
            Where-Object { $_.FolderType -eq "Calendar" } |
            Select-Object -First 1
        if ($null -eq $calendarFolder) {
            throw "The Calendar folder could not be located."
        }

        $calendarFolderIdentity = "$Identity`:\$($calendarFolder.Name)"
        @(Get-MailboxFolderPermission -Identity $calendarFolderIdentity -ErrorAction Stop)
    }
}

function Initialize-RbaResourceDelegateIdentitySets {
    $resourceDelegateIdentitySets = @($script:RbaSettings.ResourceDelegates | ForEach-Object {
            $delegateIdentity = ([string]$_).ToLowerInvariant()
            $identityAliases = [System.Collections.Generic.List[string]]::new()
            $identityAliases.Add($delegateIdentity)
            try {
                $recipient = Get-Recipient -Identity $_ -ErrorAction Stop
                if ($null -ne $recipient.PrimarySmtpAddress) {
                    $identityAliases.Add(([string]$recipient.PrimarySmtpAddress).ToLowerInvariant())
                }
            } catch {
                Write-Verbose "Unable to resolve resource delegate '$delegateIdentity' for direct Calendar permission comparison."
            }
            [PSCustomObject]@{
                aliases = @($identityAliases | Sort-Object -Unique)
            }
        })
    $script:ResourceDelegateIdentitySets = $resourceDelegateIdentitySets
    $script:ResourceDelegateIdentitySetsAvailable = $true
}

function CollectMailboxPermissions {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-MailboxPermission -Identity $Identity"
    [array]$script:MailboxPermissions = Invoke-RbaCollector -Name "MailboxPermissions" -AllowEmptyCollection -Action {
        @(Get-MailboxPermission -Identity $Identity -ErrorAction Stop)
    }
}

function EvaluateCalProcessing {

    if ($RbaSettings.AutomateProcessing -ne "AutoAccept") {
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is not set to AutoAccept. RBA will not work as configured."
        Write-Host -ForegroundColor Red "Error: For RBA to do anything AutomateProcessing must be set to AutoAccept."
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is set to $($RbaSettings.AutomateProcessing)."
        Write-Host -ForegroundColor Yellow "Use 'Set-CalendarProcessing -Identity $Identity -AutomateProcessing AutoAccept' to set AutomateProcessing to AutoAccept."
        Write-Host -ForegroundColor Red "Continuing collection and reporting."
    } else {
        Write-Host -ForegroundColor Green "AutomateProcessing is set to AutoAccept. RBA will analyze the meeting request."
    }
}

# RBA processing logic
function ProcessingLogic {
    Write-DashLineBoxColor @("RBA Processing Logic") -DashChar =
    @"
        The RBA first evaluates a request against all the policy configuration constraints assigned in the calendar
        processing object for the resource mailbox.

        This will result in the request either being in-policy or out-of-policy. The RBA then reads the recipient well
        values to determine where to send or handle in-policy requests and out-of-policy requests.

        Lastly if the Request is accepted, the PostProcessing steps will be performed.
"@
}

function RBACriteria {
    Write-DashLineBoxColor @("Policy Configuration") -Color Cyan -DashChar =

    Write-Host " The following criteria are used to determine if a meeting request is in-policy or out-of-policy. "
    Write-Host -ForegroundColor Cyan @"
    `t Setting                          Value
    `t ------------------------------  -----------------------------
    `t AllowConflicts:                 $($RbaSettings.AllowConflicts)
    `t AllowDistributionGroup:         $($RbaSettings.AllowDistributionGroup)
    `t AllowMultipleResources:         $($RbaSettings.AllowMultipleResources)
    `t MaximumDurationInMinutes:       $($RbaSettings.MaximumDurationInMinutes)
    `t MinimumDurationInMinutes:       $($RbaSettings.MinimumDurationInMinutes)
    `t AllowRecurringMeetings:         $($RbaSettings.AllowRecurringMeetings)
    `t ScheduleOnlyDuringWorkHours:    $($RbaSettings.ScheduleOnlyDuringWorkHours)
    `t ProcessExternalMeetingMessages: $($RbaSettings.ProcessExternalMeetingMessages)
    `t BookingWindowInDays:            $($RbaSettings.BookingWindowInDays)
    `t ConflictPercentageAllowed:      $($RbaSettings.ConflictPercentageAllowed)
    `t MaximumConflictInstances:       $($RbaSettings.MaximumConflictInstances)
    `t MaximumConflictPercentage:      $($RbaSettings.MaximumConflictPercentage)
    `t EnforceSchedulingHorizon:       $($RbaSettings.EnforceSchedulingHorizon)
"@
    Write-Host -NoNewline "`r`nIf all the above criteria are met, the request is "
    Write-Host -ForegroundColor Yellow -NoNewline "In-Policy."
    Write-Host -NoNewline "`r`nIf any of the above criteria are not met, the request is "
    Write-Host -ForegroundColor DarkYellow -NoNewline  "Out-of-Policy."
    Write-Host

    # RBA processing settings Verbose Output
    $RBACriteriaExtra = ""

    if ($RbaSettings.AllowConflicts -eq $true) {
        $RBACriteriaExtra += "Conflicts are accepted without percentage or count limits. This is required for Workspaces.`r`n"
    } elseif ($RbaSettings.ConflictPercentageAllowed -eq 0 `
            -and $RbaSettings.MaximumConflictInstances -eq 0) {
        $RBACriteriaExtra += "No conflicts are allowed.`r`n"
    } else {
        $RBACriteriaExtra += "For recurring meetings, the series is declined when conflicts exceed either $($RbaSettings.ConflictPercentageAllowed)% of instances or $($RbaSettings.MaximumConflictInstances) instances; otherwise, the conflicting instances are declined.`r`n"
    }

    if ($RbaSettings.AllowDistributionGroup -eq $true) {
        $RBACriteriaExtra += "Distribution groups are allowed.`r`n"
    } else {
        $RBACriteriaExtra += "Distribution groups are not allowed.`r`n"
    }

    if ($RbaSettings.AllowMultipleResources -eq $true) {
        $RBACriteriaExtra += "Multiple resources are allowed.`r`n"
    } else {
        $RBACriteriaExtra += "Multiple resources are not allowed.`r`n"
    }

    if ($RbaSettings.MaximumDurationInMinutes -gt 0) {
        $RBACriteriaExtra += "Maximum meeting duration is $($RbaSettings.MaximumDurationInMinutes) minutes.`r`n"
    }

    if ($RbaSettings.MinimumDurationInMinutes -gt 0) {
        $RBACriteriaExtra += "Minimum meeting duration is $($RbaSettings.MinimumDurationInMinutes) minutes.`r`n"
    }

    if ($RbaSettings.AllowRecurringMeetings -eq $true) {
        $RBACriteriaExtra += "Recurring meetings are allowed.`r`n"
    } else {
        $RBACriteriaExtra += "Recurring meetings are not allowed.`r`n"
    }

    if ($RbaSettings.ScheduleOnlyDuringWorkHours -eq $true) {
        $RBACriteriaExtra += "Meetings are only allowed during work hours.`r`n"
    } else {
        $RBACriteriaExtra += "Meetings are allowed at any time.`r`n"
    }

    if ($RbaSettings.EnforceSchedulingHorizon -eq $true) {
        $RBACriteriaExtra += "Recurring series that extend beyond the $($RbaSettings.BookingWindowInDays)-day booking window are declined.`r`n"
    } else {
        $RBACriteriaExtra += "Recurring series that start within the $($RbaSettings.BookingWindowInDays)-day booking window can be accepted, but occurrences beyond the window are removed.`r`n"
    }

    if ($RbaSettings.ProcessExternalMeetingMessages -eq $true) {
        $RBACriteriaExtra += "External meeting requests will be evaluated.`r`n"
    } else {
        $RBACriteriaExtra += "RBA will reject all External meeting requests.`r`n"
    }

    $RBACriteriaExtra += "The resource booking window is $($RbaSettings.BookingWindowInDays) days; 0 means today.`r`n"

    Write-Verbose $RBACriteriaExtra
}

# RBA processing settings
function RBAProcessingValidation {
    Write-DashLineBoxColor @("Policy Processing:") -DashChar =

    # check for False null False null False null - RBA is configured to do nothing.
    if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestOutOfPolicy -eq $false `
            -and $RbaSettings.BookInPolicy.Count -eq 0 `
            -and $RbaSettings.AllBookInPolicy -eq $false `
            -and $RbaSettings.RequestInPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestInPolicy -eq $false ) {
        Write-Host -ForegroundColor Red "`r`n Error: The RBA isn't configured to process items. No RBA processing of Meeting Requests will occur."
        Write-Host -ForegroundColor Red "Consider configuring the properties below to process all requests.  (Default is null, True, null, False, null, True)."
        Write-Host
        Write-Host "`t RequestOutOfPolicy:            {$($RbaSettings.RequestOutOfPolicy)}"
        Write-Host "`t AllRequestOutOfPolicy:        "$RbaSettings.AllRequestOutOfPolicy
        Write-Host "`t BookInPolicy:                  {$($RbaSettings.BookInPolicy)}"
        Write-Host "`t AllBookInPolicy:              "$RbaSettings.AllBookInPolicy
        Write-Host "`t RequestInPolicy:               {$($RbaSettings.RequestInPolicy)}"
        Write-Host "`t AllRequestInPolicy:           "$RbaSettings.AllRequestInPolicy
        Write-Host -ForegroundColor Red "Continuing collection and reporting."
    }
}

# Write out a list of Mailboxes
# We get CN from the cmdlet and want Display Name and Primary SMTP Address
function OutputMBList {
    param (
        [Parameter(Mandatory)]
        [string[]]$MBList
    )
    foreach ($User in $MBList) {
        try {
            # MS Support will error as we need the Organization to process from CN
            $Org = $Identity.Split('@')[1]

            if ($null -ne $Org) {
                $recipient = Get-Recipient -Identity $User -Organization $Org -ErrorAction Stop
            } else {
                $recipient = Get-Recipient -Identity $User -ErrorAction Stop
            }
            Write-Host " `t `t [$($recipient.DisplayName)] -- $($recipient.PrimarySmtpAddress)"
        } catch {
            Write-Warning "Unable to resolve recipient '$User': $($_.Exception.Message)"
            Write-Host " `t `t [$User]"
        }
    }
}

function InPolicyProcessing {
    # In-policy request processing
    Write-DashLineBoxColor @("  In-Policy request processing:") -Color Yellow

    if ($RbaSettings.BookInPolicy.Count -eq 0) {
        Write-Host "`t BookInPolicy:                     {$($RbaSettings.BookInPolicy)}"
    } else {
        Write-Host "`t BookInPolicy:                     These $($RbaSettings.BookInPolicy.count) accounts do not require the delegate approval."
        OutputMBList($RbaSettings.BookInPolicy)
    }
    Write-Host "`t AllBookInPolicy:                 "$RbaSettings.AllBookInPolicy
    Write-Host "`t RequestInPolicy:                  {$($RbaSettings.RequestInPolicy)}"
    Write-Host "`t AllRequestInPolicy:              "$RbaSettings.AllRequestInPolicy
    Write-Host

    if ($RbaSettings.AllBookInPolicy -eq $true) {
        Write-Host "- The RBA will process (auto-book) all in-policy meetings. (Default)"
        Write-Host "`t Note - This supersedes the all of the other in-policy setting."
    } else {
        if ($RbaSettings.BookInPolicy.Count -gt 0) {
            Write-Host "- The RBA will process (auto-book / accept) in-policy requests from this list of Users:"
            OutputMBList($RbaSettings.BookInPolicy)
        }

        Write-Host "- RBA will forward all in-policy meetings to the resource delegates."

        if ($RbaSettings.AllRequestInPolicy -eq $true) {
            Write-Host "- All users are allowed to submit in-policy requests to the resource delegates."
        } else {
            Write-Host "- Users are not allowed to submit request for this resource. (Default)"
        }
    }
}

# Out-of-policy request processing
function OutOfPolicyProcessing {
    Write-DashLineBoxColor @("  Out-of-Policy request processing:") -Color DarkYellow
    if ($RbaSettings.RequestOutOfPolicy.Count -gt 0) {
        Write-Host "`t RequestOutOfPolicy:           These {$($RbaSettings.RequestOutOfPolicy.Count)} accounts are allowed to submit out-of-policy requests (that require approval by a resource delegate)."
        OutputMBList($RbaSettings.RequestOutOfPolicy)
    } else {
        Write-Host "`t RequestOutOfPolicy:               {$($RbaSettings.RequestOutOfPolicy)}"
    }
    Write-Host "`t AllRequestOutOfPolicy:           "$RbaSettings.AllRequestOutOfPolicy

    if ($RbaSettings.AllRequestOutOfPolicy -eq $true ) {
        Write-Host -ForegroundColor Yellow "Information: - All users are allowed to submit out-of-policy requests to the resource mailbox. Out-of-policy requests require approval by a resource mailbox delegate."

        if ($RbaSettings.RequestOutOfPolicy.count -gt 0) {
            Write-Host -ForegroundColor Magenta "Warning: The users that are listed in RequestOutOfPolicy are overridden by the AllRequestOutOfPolicy as everyone can submit out of policy requests."
        }
    } else {
        if ($RbaSettings.RequestOutOfPolicy.count -eq 0) {
            Write-Host "- No User can submit out-of-policy requests to this resource mailbox. (Default)"
        } else {
            Write-Host "- Only the users in the RequestOutOfPolicy list can submit out-of-policy requests to this resource mailbox."
        }
    }
}

# RBA Delegate Settings
function RBADelegateSettings {
    Write-DashLineBoxColor @("Resource Delegate Settings") -Color White

    if ($RbaSettings.ResourceDelegates.Count -eq 0) {
        Write-Host "`t ResourceDelegates:               "$RbaSettings.ResourceDelegates
    } else {
        Write-Host "`t ResourceDelegates:               $($RbaSettings.ResourceDelegates.Count) Resource Delegate`(s`) have been configured."
        OutputMBList($RbaSettings.ResourceDelegates)
    }

    Write-Host "`t AddNewRequestsTentatively:       "$RbaSettings.AddNewRequestsTentatively
    Write-Host "`t ForwardRequestsToDelegates:      "$RbaSettings.ForwardRequestsToDelegates
    Write-Host

    # Check for known configuration issues to warn about:
    if ($RbaSettings.ResourceDelegates.Count -gt 0) {
        if ($RbaSettings.AddNewRequestsTentatively -eq $true) {
            Write-Host "In-policy meetings will be marked tentative and the meeting request will be sent to the Resource Delegates to be accepted or rejected. Default"
        } else {
            Write-Host -ForegroundColor Yellow "Warning: Only existing calendar items will be updated by the Calendar Attendant."
        }

        if ($RbaSettings.ForwardRequestsToDelegates -eq $true ) {
            if ($RbaSettings.AllBookInPolicy -eq $true) {
                Write-Host -ForegroundColor White "Information: Delegate(s) will not receive any In Policy requests as they will be AutoApproved."
            } elseif ($RbaSettings.BookInPolicy.Count -gt 0 ) {
                Write-Host -ForegroundColor White "Information: Delegate(s) will not receive requests from users in the BookInPolicy as they will be AutoApproved."
                OutputMBList($RbaSettings.BookInPolicy)
            }

            if ($RbaSettings.AllRequestOutOfPolicy -eq $false) {
                if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 ) {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate(s) will not receive any Out of Policy requests as they will all be AutoDenied."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate(s) will only receive any Out of Policy requests from the below list of users."
                    OutputMBList($RbaSettings.RequestOutOfPolicy)
                }
            } else {
                Write-Host -ForegroundColor Yellow "Warning: All users can send Out of Policy requests to be approved by the Resource Delegates."
            }
        }
    } else {
        Write-Host -ForegroundColor Yellow "Warning: No Delegates are configured."
        if ($RbaSettings.ForwardRequestsToDelegates -eq $true -and
            $RbaSettings.AllBookInPolicy -ne $true ) {
            Write-Host -ForegroundColor Yellow "Warning: ForwardRequestsToDelegates is true but there are no Delegates."
        } if ($RbaSettings.RequestOutOfPolicy.Count -gt 0) {
            Write-Host -ForegroundColor Red "Error: Users are listed in RequestOutOfPolicy but there are no Delegates. - All Out of policy requests by these users will be Tentatively accepted."
        } if ($RbaSettings.AllRequestOutOfPolicy -eq $true) {
            Write-Host -ForegroundColor Red "Error: AllRequestOutOfPolicy is set but there are no Delegates. - All Out of policy requests will be Tentatively accepted."
        }
    }
}

# RBA PostProcessing Steps
function RBAPostProcessing {
    Write-DashLineBoxColor @("PostProcessing Setup") -Color Cyan -DashChar =
    Write-Host -ForegroundColor Cyan "The RBA will format the meeting based on the following settings."

    #    Write-Host -ForegroundColor Cyan "`r`n`t RBA PostProcessing Steps";
    #    Write-Host -ForegroundColor Cyan "`t ------------------------------------   ---------------------------------";
    Write-Host -ForegroundColor Cyan @"
    `t AddOrganizerToSubject:                $($RbaSettings.AddOrganizerToSubject)
    `t DeleteSubject:                        $($RbaSettings.DeleteSubject)
    `t DeleteComments (Meeting body):        $($RbaSettings.DeleteComments)
    `t DeleteAttachments:                    $($RbaSettings.DeleteAttachments)
    `t RemovePrivateProperty:                $($RbaSettings.RemovePrivateProperty)
    `t DeleteNonCalendarItems:               $($RbaSettings.DeleteNonCalendarItems)
    `t RemoveForwardedMeetingNotifications:  $($RbaSettings.RemoveForwardedMeetingNotifications)
    `t RemoveCanceledMeetings:               $($RbaSettings.RemoveCanceledMeetings)
    `t EnableAutoRelease:                    $($RbaSettings.EnableAutoRelease)
    `t AddAdditionalResponse:                $($RbaSettings.AddAdditionalResponse)
"@

    # Warning about the DeleteComments setting and Teams:
    if ($RbaSettings.DeleteComments -eq $true) {
        Write-Host -ForegroundColor Yellow "Warning: DeleteComments is set to true. This will remove the Teams information which is in the meeting body."
    }
}

# RBA Verbose PostProcessing Steps
function VerbosePostProcessing {
    Write-Verbose "`t`r`n AdditionalResponse:                   `r`n$($RbaSettings.AdditionalResponse)`r`n`r`n"

    $RbaFormattingString = "Description of the RBA Post Processing Steps:`r`n"
    if ($RbaSettings.DeleteSubject -eq $true) {
        if ($RbaSettings.AddOrganizerToSubject -eq $true) {
            $RbaFormattingString += "The RBA will delete the subject and add the organizer to the subject. (Default)"
        } else {
            $RbaFormattingString += "The RBA will delete the subject. Consider adding the organizer to the subject with the AddOrganizerToSubject property."
        }
    } elseif ($RbaSettings.AddOrganizerToSubject -eq $true) {
        $RbaFormattingString += "The RBA will add the organizer to the subject."
    } else {
        $RbaFormattingString += "The RBA will not change the subject property."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteComments -eq $true) {
        $RbaFormattingString += "The RBA will remove the meeting body. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the meeting body."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteAttachments -eq $true) {
        $RbaFormattingString += "The RBA will remove all Attachments. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the Attachments."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemovePrivateProperty -eq $true) {
        $RbaFormattingString += "The RBA will remove the private property. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the private property."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteNonCalendarItems -eq $true) {
        $RbaFormattingString += "The RBA will remove all non-calendar items sent to the resource mailbox. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not remove the non-calendar items."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemoveForwardedMeetingNotifications -eq $true) {
        $RbaFormattingString += "The RBA will remove all forwarded meeting notifications."
    } else {
        $RbaFormattingString += "The RBA will not change the forwarded meeting notifications. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemoveCanceledMeetings -eq $true) {
        $RbaFormattingString += "The RBA will remove all canceled meetings."
    } else {
        $RbaFormattingString += "The RBA will not change the canceled meetings. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.EnableAutoRelease -eq $true) {
        $RbaFormattingString += "The RBA will automatically release the meeting if the resource is available."
    } else {
        $RbaFormattingString += "The RBA will not automatically release the meeting. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.AddAdditionalResponse -eq $true -and $RbaSettings.AdditionalResponse.Length -gt 0) {
        $RbaFormattingString += "The RBA will add the following additional response to the meeting: " +
        $RbaSettings.AdditionalResponse + "."
    } else {
        $RbaFormattingString += "The RBA will not add the additional response."
    }
    $RbaFormattingString += [environment]::Newline

    Write-Verbose $RbaFormattingString
}

#Add information about RBA logs.
function RBAPostScript {
    Write-Host
    Write-Host "If more information is needed about this resource mailbox, please look at the RBA logs saved in this directory to
        see how the system proceed the meeting request."
    Write-Host "To get new RBA Logs, run the following command:"
    Write-Host -ForegroundColor Yellow "`tExport-MailboxDiagnosticLogs $Identity -ComponentName RBA"
    Write-Host
    Write-Host "To continue troubleshooting further, suggestion is to create a Test Meeting and send it to this room, making sure that the meeting is in the future, as the RBA does not process meeting in the past)."
    Write-Host "Then pull the RBA Logs as well as the Calendar Diagnostic Objects for the Meeting Organizer and the Room to see how the system processed the meeting request."
    Write-Host "For Calendar Diagnostic Objects, try [CalLogSummaryScript](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-CalendarDiagnosticObjectsSummary.ps1)"

    Write-Host "`n`rIf you found an error with this script or a misconfigured RBA case that this should cover,
         send mail to Shanefe@microsoft.com"
}

function CollectRBALog {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName RBA"
    $diagnosticLog = Invoke-RbaCollector -Name "RbaLog" -Action {
        Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName RBA -ErrorAction Stop
    }

    if ($null -ne $diagnosticLog) {
        [array]$script:RBALog = $diagnosticLog.MailboxLog -split "`r?`n"
    }
}

function Get-RbaMeetingIdsFromLogLines {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Lines
    )

    $meetingIds = [System.Collections.Generic.List[string]]::new()
    $content = $Lines -join [Environment]::NewLine
    $labelPattern = '(?i)(?:CleanGlobalObjectId|GlobalObjectId|Global Object Id|MeetingId|Meeting ID|UID)\s*[:=]\s*[\[\{]?(?<MeetingId>[A-Za-z0-9+/=_-]{16,})'
    foreach ($match in [regex]::Matches($content, $labelPattern)) {
        $meetingIds.Add(($match.Groups['MeetingId'].Value -replace ',', ''))
    }

    $processRequestPattern = '(?i)\bBegin Process(?:Update)?Request\s+Goid:\s*[\[\{]?(?<MeetingId>[A-Za-z0-9+/=_,-]{16,})'
    foreach ($match in [regex]::Matches($content, $processRequestPattern)) {
        $meetingIds.Add(($match.Groups['MeetingId'].Value -replace ',', ''))
    }

    foreach ($match in [regex]::Matches($content, '(?i)\b040000008,?[A-F0-9]{23,}\b')) {
        $meetingIds.Add(($match.Value -replace ',', ''))
    }

    return @($meetingIds | Sort-Object -Unique)
}

function Split-RbaLogProcessingBlocks {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Lines
    )

    if ($Lines.Count -eq 0) {
        return @()
    }

    $exactStartPattern = 'START - HandleEventInternal Automatic Booking is enabled for resource\.\s*$'
    $startIndexes = @(0..($Lines.Count - 1) | Where-Object { $Lines[$_] -match $exactStartPattern })
    $blocks = [System.Collections.Generic.List[object]]::new()

    if ($startIndexes.Count -eq 0) {
        $blocks.Add([PSCustomObject]@{
                sequence           = 1
                startLine          = 1
                endLine            = $Lines.Count
                startBoundaryFound = $false
                boundaryStatus     = "MissingStartBoundary"
                startMarker        = $null
                startTimeText      = $null
                meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $Lines)
                lines              = @($Lines)
            })
        return $blocks.ToArray()
    }

    for ($blockIndex = 0; $blockIndex -lt $startIndexes.Count; $blockIndex++) {
        $endIndex = $startIndexes[$blockIndex]
        $startIndex = if ($blockIndex -eq 0) {
            0
        } else {
            $startIndexes[$blockIndex - 1] + 1
        }
        $blockLines = @($Lines[$startIndex..$endIndex])
        $startMarker = [string]$Lines[$endIndex]
        $startTimeText = if ($startMarker.Contains(',')) {
            ($startMarker -split ',', 2)[0].Trim()
        } else {
            $null
        }
        $blocks.Add([PSCustomObject]@{
                sequence           = $blockIndex + 1
                startLine          = $startIndex + 1
                endLine            = $endIndex + 1
                startBoundaryFound = $true
                boundaryStatus     = $(if ($blockIndex -eq 0) { "SourceStartToExactStart" } else { "BetweenExactStartBoundaries" })
                startMarker        = $startMarker
                startTimeText      = $startTimeText
                meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $blockLines)
                lines              = $blockLines
            })
    }

    $lastStartIndex = $startIndexes[-1]
    if ($lastStartIndex -lt ($Lines.Count - 1)) {
        $partialLines = @($Lines[($lastStartIndex + 1)..($Lines.Count - 1)])
        if (@($partialLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            $blocks.Add([PSCustomObject]@{
                    sequence           = $blocks.Count + 1
                    startLine          = $lastStartIndex + 2
                    endLine            = $Lines.Count
                    startBoundaryFound = $false
                    boundaryStatus     = "MissingStartBoundary"
                    startMarker        = $null
                    startTimeText      = $null
                    meetingIds         = @(Get-RbaMeetingIdsFromLogLines -Lines $partialLines)
                    lines              = $partialLines
                })
        }
    }

    return $blocks.ToArray()
}

function Test-RbaLogLinesContainText {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [string]$Text
    )

    foreach ($line in $Lines) {
        if ($line.IndexOf($Text, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Get-RbaTargetedLogBlockObject {
    param(
        [Parameter(Mandatory)]
        [object]$Block,

        [Parameter(Mandatory)]
        [bool]$SubjectMatched
    )

    $actions = @($Block.lines | ForEach-Object {
            foreach ($match in [regex]::Matches($_, '(?i)Action:(?<Action>Accept|Decline|Tentative)')) {
                $match.Groups['Action'].Value
            }
        } | Sort-Object -Unique)

    return [PSCustomObject]@{
        sequence                   = $Block.sequence
        startLine                  = $Block.startLine
        endLine                    = $Block.endLine
        startBoundaryFound         = $Block.startBoundaryFound
        boundaryStatus             = $Block.boundaryStatus
        startMarker                = $Block.startMarker
        startTimeText              = $Block.startTimeText
        eventTimeText              = $Block.startTimeText
        rawLogOrder                = "NewestFirst"
        chronologicalReadDirection = "BottomToTop"
        subjectMatched             = $SubjectMatched
        meetingIds                 = @($Block.meetingIds)
        actions                    = $actions
        updateDetected             = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Begin ProcessUpdateRequest'
        cancellationDetected       = Test-RbaLogLinesContainText -Lines $Block.lines -Text "It's a meeting cancellation."
        delegateReferralDetected   = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Forwarding Request To Delegates'
        externalProcessingSkipped  = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Skipping processing because user settings for processing external items is false.'
        horizonDeclineDetected     = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Recurrence ends is past the booking window. Meeting will be declined.'
        recurrenceTruncateDetected = Test-RbaLogLinesContainText -Lines $Block.lines -Text 'Truncating meeting recurrence end window'
        rawLog                     = @($Block.lines)
    }
}

function Get-RbaMeetingLogSearchObject {
    if ([string]::IsNullOrWhiteSpace($MeetingSubject)) {
        return [PSCustomObject]@{
            searchSubject                    = $null
            status                           = "NotRequested"
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = @()
            eventCount                       = 0
            acceptCount                      = 0
            tentativeCount                   = 0
            declineCount                     = 0
            updateCount                      = 0
            cancellationCount                = 0
            delegateReferralCount            = 0
            externalSkippedCount             = 0
            horizonDeclineCount              = 0
            recurrenceTruncateCount          = 0
            events                           = @()
        }
    }

    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        return [PSCustomObject]@{
            searchSubject                    = $MeetingSubject
            status                           = "LogUnavailable"
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = @()
            eventCount                       = 0
            updateCount                      = 0
            cancellationCount                = 0
            declineCount                     = 0
            events                           = @()
        }
    }

    $blocks = @(Split-RbaLogProcessingBlocks -Lines @($script:RBALog))
    $subjectBlocks = @($blocks | Where-Object {
            Test-RbaLogLinesContainText -Lines $_.lines -Text $MeetingSubject
        })
    if ($subjectBlocks.Count -eq 0) {
        return [PSCustomObject]@{
            searchSubject                    = $MeetingSubject
            status                           = "NotFound"
            sourceOrder                      = "NewestFirst"
            eventOrder                       = "NewestFirst"
            rawLogChronologicalReadDirection = "BottomToTop"
            subjectMatchCount                = 0
            meetingIds                       = @()
            eventCount                       = 0
            updateCount                      = 0
            cancellationCount                = 0
            declineCount                     = 0
            events                           = @()
        }
    }

    $meetingIds = @($subjectBlocks.meetingIds | Sort-Object -Unique)
    $selectedBlocks = if ($meetingIds.Count -gt 0) {
        @($blocks | Where-Object {
                $blockMeetingIds = @($_.meetingIds)
                @($blockMeetingIds | Where-Object { $_ -in $meetingIds }).Count -gt 0 -or
                (Test-RbaLogLinesContainText -Lines $_.lines -Text $MeetingSubject)
            })
    } else {
        $subjectBlocks
    }

    $events = @($selectedBlocks | ForEach-Object {
            Get-RbaTargetedLogBlockObject -Block $_ `
                -SubjectMatched (Test-RbaLogLinesContainText -Lines $_.lines -Text $MeetingSubject)
        })
    $status = if ($meetingIds.Count -gt 0) { "Found" } else { "FoundWithoutMeetingId" }

    return [PSCustomObject]@{
        searchSubject                    = $MeetingSubject
        status                           = $status
        sourceOrder                      = "NewestFirst"
        eventOrder                       = "NewestFirst"
        rawLogChronologicalReadDirection = "BottomToTop"
        subjectMatchCount                = $subjectBlocks.Count
        meetingIds                       = $meetingIds
        eventCount                       = $events.Count
        acceptCount                      = @($events | Where-Object { $_.actions -contains "Accept" }).Count
        tentativeCount                   = @($events | Where-Object { $_.actions -contains "Tentative" }).Count
        declineCount                     = @($events | Where-Object { $_.actions -contains "Decline" }).Count
        updateCount                      = @($events | Where-Object { $_.updateDetected }).Count
        cancellationCount                = @($events | Where-Object { $_.cancellationDetected }).Count
        delegateReferralCount            = @($events | Where-Object { $_.delegateReferralDetected }).Count
        externalSkippedCount             = @($events | Where-Object { $_.externalProcessingSkipped }).Count
        horizonDeclineCount              = @($events | Where-Object { $_.horizonDeclineDetected }).Count
        recurrenceTruncateCount          = @($events | Where-Object { $_.recurrenceTruncateDetected }).Count
        events                           = $events
    }
}

function RBALogSummary {
    Write-DashLineBoxColor @("RBA Log Summary") -Color Blue -DashChar =

    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        Write-Warning "RBA Log summary could not be evaluated because the log is unavailable."
        return
    }

    if ($script:RBALog.count -gt 1) {
        Write-Host "`tFound $($script:RBALog.count) RBA Log entries in RBALog.  Summarizing Accepts, Declines, and Tentative meetings."
        $Starts = $script:RBALog | Select-String -Pattern "START -"
        $FirstDate = "[Unknown]"
        $LastDate = "[Unknown]"

        if ($starts.count -gt 1) {
            $LastDate = ($Starts[0] -split ",")[0].Trim()
            $FirstDate = ($starts[$($Starts.count) -1 ] -split ",")[0].Trim()
            Write-Host "`tThe RBA Log for [$Identity] shows the following:"
            Write-Host "`t $($starts.count) Processed events times between $FirstDate and $LastDate"
        }

        $AcceptLogs = $script:RBALog | Select-String -Pattern "Action:Accept"
        $DeclineLogs = $script:RBALog | Select-String -Pattern "Action:Decline"
        $TentativeLogs = $script:RBALog | Select-String -Pattern "Action:Tentative"
        $UpdatedLogs = $script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest"
        $SkippedExternal = $script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false."
        $DelegateReferrals = $script:RBALog | Select-String -Pattern "Forwarding Request To Delegates"
        $NonMeetingRequests = $script:RBALog | Select-String -Pattern "Item is not a meeting request"
        $Cancellations = $script:RBALog | Select-String -Pattern "It's a meeting cancellation."

        if ($AcceptLogs.count -ne 0) {
            $LastAccept = ($AcceptLogs[0] -split ",")[0].Trim()
            Write-Host "`t $($AcceptLogs.count) were Accepted between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Accepted on $LastAccept"
        }

        if ($TentativeLogs.count -ne 0) {
            $LastTentative = ($TentativeLogs[0] -split ",")[0].Trim()
            Write-Host "`t $($TentativeLogs.count) Tentatively Accepted meetings between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Tentatively Accepted on $LastTentative"
        }

        if ($DeclineLogs.count -ne 0) {
            $LastDecline = ($DeclineLogs[0] -split ",")[0].Trim()
            Write-Host "`t $($DeclineLogs.count) Declined meetings between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Declined on $LastDecline"
        }

        if ($AcceptLogs.count -eq 0 -and $TentativeLogs.count -eq 0 -and $DeclineLogs.count -eq 0) {
            Write-Host -ForegroundColor Red "`t No meetings were processed in the RBA Log."
        }

        if ($UpdatedLogs.count -ne 0) {
            $LastUpdated = ($UpdatedLogs[0] -split ",")[0].Trim()
            Write-Host "`t $($UpdatedLogs.count) Updates to meetings between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting updated on $LastUpdated"
        } else {
            Write-Host -ForegroundColor Red "`t No meetings were updated in the RBA Log."
        }

        if ($Cancellations.count -ne 0) {
            Write-Host "`t $($Cancellations.count) Cancellations were processed."
        } else {
            Write-Host "`t No meetings were canceled in the RBA Log."
        }

        if ($DelegateReferrals.count -ne 0) {
            $LastDelegateReferral = ($DelegateReferrals[0] -split ",")[0].Trim()
            Write-Host "`t $($DelegateReferrals.count) Delegate Referrals were sent between $FirstDate and $LastDate"
            Write-Host "`t`t with the last Delegate Referral sent on $LastDelegateReferral"
        } else {
            Write-Host "`t No Delegate Referrals were sent in the RBA Log."
        }

        if ($NonMeetingRequests.count -ne 0) {
            $LastNonMeetingRequest = ($NonMeetingRequests[0] -split ",")[0].Trim()
            Write-Host "`t $($NonMeetingRequests.count) Non Meeting Requests were skipped between $FirstDate and $LastDate"
            Write-Host "`t`t with the last Non Meeting Request skipped on $LastNonMeetingRequest"
        } else {
            Write-Host "`t No Non Meeting Requests were skipped in the RBA Log."
        }

        if ($SkippedExternal.count -ne 0) {
            if ($SkippedExternal.Count -lt 3) {
                Write-Host "`t Warning: $($SkippedExternal.count) External meetings were skipped as processing external items is false."
            } else {
                Write-Host -ForegroundColor Red "`t Warning: $($SkippedExternal.count) External meetings were skipped as processing external items is false."
                Write-Host -ForegroundColor Red "`t`t Many skipped external meetings may indicate a configuration issue in Transport."
                Write-Host -ForegroundColor Red "`t`t Validate that Internal Meetings are not getting marked as External."
            }
        }

        $Filename = "RBA-Logs_$($Identity.Split('@')[0])_$runTimestamp.txt"
        Write-Host "`r`n`t RBA Logs saved as [" -NoNewline
        Write-Host -ForegroundColor Cyan $Filename -NoNewline
        Write-Host "] in the current directory."
        $script:RBALog.replace(", Entry Action: Message, LogComment", "").replace("Mailbox: ", "") |
            Out-File -FilePath $Filename

        RBAPostScript
    } else {
        Write-Warning "No RBA Logs found.  Send a test meeting invite to the room and try again if this is a newly created room mailbox."
    }
}

#Validate Workspace settings
function ValidateWorkspace {
    Write-DashLineBoxColor @("Workspace Settings") -Color White
    Write-Host  -ForegroundColor White "`tIs Resource [$Identity] a Workspace: $(if ($script:Workspace) {"TRUE"} else {"False - Skipping additional Workspace Checks"})."

    if ($script:Workspace) {
        if ([string]::IsNullOrEmpty($script:Place.Capacity)) {
            Write-Host -ForegroundColor Red "`tError: Required Property 'Capacity' is not set for [$Identity]."
            Write-Host -ForegroundColor White "`tRun " -NoNewline
            Write-Host -ForegroundColor Yellow "Set-Place $Identity -Capacity <Value> " -NoNewline
            Write-Host -ForegroundColor White "to set the required properties on the resource."
        } else {
            Write-Host -ForegroundColor Green "`tRequired Property 'Capacity' is set to $($script:Place.Capacity)."
        }

        $requiredWorkspaceSettings = @("EnforceCapacity", "AllowConflicts")

        foreach ($prop in $requiredWorkspaceSettings) {
            if ($RbaSettings.$prop -ne $true) {
                $requiredWorkspaceSettingsMissing = $true
                Write-Host -ForegroundColor Red "`tError: Required Property '$prop' is not set to '$true' for $Identity."
                Write-Debug "[$Identity].[$prop] is set to: $($RbaSettings.$prop)."
            } else {
                Write-Host -ForegroundColor Green "`tRequired Property '$prop' is set to $($RbaSettings.$prop)."
            }
        }
        if ($requiredWorkspaceSettingsMissing) {
            Write-Host -ForegroundColor White "`tOne or more properties that are required to be true are not. Run the following cmdlet to set the required properties:"
            Write-Host -ForegroundColor White "`tRun " -NoNewline
            Write-Host -ForegroundColor Yellow "'Set-CalendarProcessing $Identity -EnforceCapacity `$True -AllowConflicts `$True' " -NoNewline
            Write-Host -ForegroundColor White "to set the properties to true."
        }

        Write-Host -ForegroundColor White "`tLearn more about configuring Workspaces at: " -NoNewline
        Write-Host -ForegroundColor Yellow "https://learn.microsoft.com/en-us/exchange/troubleshoot/outlook-issues/create-book-workspace-outlook"
    }
}

# Validate Setting for the New Room List functionality
function ValidateRoomListSettings {
    Write-DashLineBoxColor @("Room List Settings") -Color White
    Write-Host -ForegroundColor White "`tThe new Room Finder uses the City and other properties to help users find the right room for their meeting."
    Write-Host -ForegroundColor White "`tTags can be used to list features of this room (i.e. Projector, etc.) so that users can narrow down their search for conference rooms."

    Write-Host -ForegroundColor White "`tLearn more at " -NoNewline
    Write-Host -ForegroundColor Yellow "https://learn.microsoft.com/en-us/outlook/troubleshoot/calendaring/configure-room-finder-rooms-workspaces`n"

    if ([string]::IsNullOrEmpty($Place.Localities)) {
        ## validate Localities
        Write-Host -ForegroundColor Yellow "`tWarning: Resource [$Identity] is not part of any Room Lists."
        Write-Host -ForegroundColor Yellow "`tWarning: Adding this resource to a Room Lists can take 24 hours to be fully propagated."
    }

    $requiredProperties = @("City", "Floor", "Capacity")

    foreach ($prop in $requiredProperties) {
        if ([string]::IsNullOrEmpty($script:Place.$prop)) {
            $requiredPropertiesMissing = $true
            Write-Host -ForegroundColor Magenta "`tWarning: Required Property '$prop' is not set for $Identity. RoomList functionality may not work as expected."
        } else {
            Write-Host -ForegroundColor Green "`tRequired Property '$prop' is set to $($script:Place.$prop)."
        }
    }

    if ($requiredPropertiesMissing) {
        Write-Host -ForegroundColor White "`tOne or more required properties are missing. Run the following cmdlet to set the required properties:"
        Write-Host -ForegroundColor White "`tRun " -NoNewline
        Write-Host -ForegroundColor Yellow "Set-Place $Identity -<prop> <Value> " -NoNewline
        Write-Host -ForegroundColor White "to set the required properties on the resource."
    }

    Write-Host -ForegroundColor White "`r`n`t New Room List commonly populated information:"
    Write-Host -ForegroundColor White "`t ----------------------------------------- "
    Write-Host -ForegroundColor White @"
    `t Address Info
    `t Street:              $($script:Place.Street)
    `t City:                $($script:Place.City)
    `t State:               $($script:Place.State)
    `t PostalCode:          $($script:Place.PostalCode)
    `t CountryOrRegion:     $($script:Place.CountryOrRegion)
    `t Building Info
    `t Building:            $($script:Place.Building)
    `t Floor:               $($script:Place.Floor)
    `t --Tags describing features and equipment in the Room
    `t Tags:                $($script:Place.Tags)
    `t --This room belongs to the following Room Lists (Localities).
    `t Localities:          $($Place.Localities)

    `t To update any of the above information, run 'Set-Place $Identity -<Property> <Value>'.
    `t For more information on this command, see
"@
    Write-Host -ForegroundColor Yellow "`t https://learn.microsoft.com/en-us/powershell/module/exchange/set-place?view=exchange-ps"
    Write-Host
}

function Write-DashLineBoxColor {
    [CmdletBinding()]
    param(
        [string[]]$Line,
        [string] $Color = "White",
        [char] $DashChar = "-"
    )
    <#
        This is to simply create a quick and easy display around a line
        -------------------------------------
        Line                           Length
        Line                           Length
        -------------------------------------
        # Empty Line
    #>
    $highLineLength = 0
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    $dashLine = [string]::Empty
    1..$highLineLength | ForEach-Object { $dashLine += $DashChar }
    Write-Host
    Write-Host -ForegroundColor $Color $dashLine
    $Line | ForEach-Object { Write-Host -ForegroundColor $Color $_ }
    Write-Host -ForegroundColor $Color $dashLine
    Write-Host
}

function Invoke-RbaCollectorOperation {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action
    )

    $ErrorActionPreference = "Stop"
    try {
        & $Action
    } catch {
        # Invoke-RbaCollector owns failures raised during collection. The operation wrapper owns
        # failures before collection or after a successful collection, such as evidence processing.
        if ($script:collectorStatuses.Contains($Name) -and
            $script:collectorStatuses[$Name].status -eq "Failed") {
            return
        }

        $errorInfo = ConvertTo-RbaErrorInfo -ErrorRecord $_
        $script:collectorStatuses[$Name] = [PSCustomObject]@{
            status                = "Failed"
            error                 = $errorInfo.message
            exceptionType         = $errorInfo.exceptionType
            category              = $errorInfo.category
            fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
            innerExceptionMessage = $errorInfo.innerExceptionMessage
        }
        $script:collectionErrors.Add([PSCustomObject]@{
                collector             = $Name
                message               = $errorInfo.message
                exceptionType         = $errorInfo.exceptionType
                category              = $errorInfo.category
                fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
                innerExceptionMessage = $errorInfo.innerExceptionMessage
            })
        Write-Warning "$Name collection failed: $($errorInfo.message)"
    }
}

function Invoke-RbaEvaluation {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action
    )

    try {
        & $Action
    } catch {
        $errorInfo = ConvertTo-RbaErrorInfo -ErrorRecord $_
        $script:evaluationErrors.Add([PSCustomObject]@{
                evaluation            = $Name
                message               = $errorInfo.message
                exceptionType         = $errorInfo.exceptionType
                category              = $errorInfo.category
                fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
                innerExceptionMessage = $errorInfo.innerExceptionMessage
            })
        Write-Warning "$Name evaluation was skipped after an error: $($errorInfo.message)"
    }
}

function Add-RbaFinding {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Findings,

        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [ValidateSet("Critical", "Error", "Warning", "Information")]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet("Detected", "NotDetected", "NotEvaluated", "NotApplicable")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Title,

        [AllowNull()]
        [object]$Evidence
    )

    $Findings.Add([PSCustomObject]@{
            ruleId   = $RuleId
            severity = $Severity
            status   = $Status
            title    = $Title
            evidence = $Evidence
        })
}

function Get-RbaFindings {
    $findings = [System.Collections.Generic.List[object]]::new()
    $mailboxAvailable = $script:collectorStatuses["Mailbox"].status -eq "Success"
    $placeAvailable = $script:collectorStatuses["Place"].status -eq "Success"
    $rulesAvailable = $script:collectorStatuses["InboxRules"].status -eq "Success"
    $settingsAvailable = $script:collectorStatuses["CalendarProcessing"].status -eq "Success"
    $logAvailable = $script:collectorStatuses["RbaLog"].status -eq "Success"
    $calendarPermissionsAvailable = $script:collectorStatuses["CalendarFolderPermissions"].status -eq "Success"
    $mailboxPermissionsAvailable = $script:collectorStatuses["MailboxPermissions"].status -eq "Success"

    Add-RbaFinding -Findings $findings -RuleId "RBA001" -Severity Error `
        -Status $(if ($mailboxAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Mailbox evidence unavailable" -Evidence $script:collectorStatuses["Mailbox"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA002" -Severity Error `
        -Status $(if ($placeAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Place evidence unavailable" -Evidence $script:collectorStatuses["Place"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA003" -Severity Error `
        -Status $(if ($rulesAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Inbox rule evidence unavailable" -Evidence $script:collectorStatuses["InboxRules"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA004" -Severity Error `
        -Status $(if ($settingsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Calendar processing evidence unavailable" -Evidence $script:collectorStatuses["CalendarProcessing"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA005" -Severity Warning `
        -Status $(if ($logAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "RBA log evidence unavailable" -Evidence $script:collectorStatuses["RbaLog"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA006" -Severity Warning `
        -Status $(if ($calendarPermissionsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Calendar folder permission evidence unavailable" -Evidence $script:collectorStatuses["CalendarFolderPermissions"].error

    Add-RbaFinding -Findings $findings -RuleId "RBA007" -Severity Warning `
        -Status $(if ($mailboxPermissionsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Mailbox permission evidence unavailable" -Evidence $script:collectorStatuses["MailboxPermissions"].error

    $mailboxIsSoftDeleted = $mailboxAvailable -and $script:MailboxObjectState -eq "SoftDeleted"
    $invalidMailboxType = $mailboxAvailable -and -not $mailboxIsSoftDeleted -and
    $script:Mailbox.RecipientTypeDetails -notin @("RoomMailbox", "EquipmentMailbox")
    Add-RbaFinding -Findings $findings -RuleId "RBA100" -Severity Critical `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIsSoftDeleted) { "NotApplicable" } elseif ($invalidMailboxType) { "Detected" } else { "NotDetected" }) `
        -Title "Mailbox type is not supported by RBA" -Evidence $script:Mailbox.RecipientTypeDetails

    Add-RbaFinding -Findings $findings -RuleId "RBA101" -Severity Critical `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIsSoftDeleted) { "Detected" } else { "NotDetected" }) `
        -Title "Resource mailbox is soft-deleted" `
        -Evidence @{ objectState = $script:MailboxObjectState; recipientTypeDetails = $script:Mailbox.RecipientTypeDetails }

    $mailboxIdentitySummary = Get-RbaMailboxIdentitySummaryObject
    Add-RbaFinding -Findings $findings -RuleId "RBA102" -Severity Information `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIdentitySummary.inputIdentityMatch -eq "ProxyAddress") { "Detected" } else { "NotDetected" }) `
        -Title "Input identity resolved through a proxy address" `
        -Evidence @{ inputIdentityMatch = $mailboxIdentitySummary.inputIdentityMatch; primarySmtpAddress = $mailboxIdentitySummary.primarySmtpAddress }

    $delegateRules = @($script:InboxRules | Where-Object { $_.Name -like "Delegate Rule*" })
    Add-RbaFinding -Findings $findings -RuleId "RBA200" -Severity Critical `
        -Status $(if (-not $rulesAvailable) { "NotEvaluated" } elseif ($delegateRules.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Delegate inbox rule can block RBA" -Evidence @{ count = $delegateRules.Count }

    $redactedRules = @($script:InboxRules | Where-Object { $_.Name -like "REDACTED-*" })
    Add-RbaFinding -Findings $findings -RuleId "RBA201" -Severity Warning `
        -Status $(if (-not $rulesAvailable) { "NotEvaluated" } elseif ($redactedRules.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Inbox rule visibility is redacted" -Evidence @{ count = $redactedRules.Count }

    Add-RbaFinding -Findings $findings -RuleId "RBA300" -Severity Critical `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AutomateProcessing -ne "AutoAccept") { "Detected" } else { "NotDetected" }) `
        -Title "AutomateProcessing is not AutoAccept" -Evidence $RbaSettings.AutomateProcessing

    $noProcessingRoutes = $settingsAvailable -and $RbaSettings.RequestOutOfPolicy.Count -eq 0 -and
    $RbaSettings.AllRequestOutOfPolicy -eq $false -and $RbaSettings.BookInPolicy.Count -eq 0 -and
    $RbaSettings.AllBookInPolicy -eq $false -and $RbaSettings.RequestInPolicy.Count -eq 0 -and
    $RbaSettings.AllRequestInPolicy -eq $false
    Add-RbaFinding -Findings $findings -RuleId "RBA301" -Severity Critical `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($noProcessingRoutes) { "Detected" } else { "NotDetected" }) `
        -Title "RBA has no configured processing route" -Evidence $noProcessingRoutes

    Add-RbaFinding -Findings $findings -RuleId "RBA302" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "A resource booking window is configured" `
        -Evidence @{ bookingWindowInDays = $RbaSettings.BookingWindowInDays; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon }

    Add-RbaFinding -Findings $findings -RuleId "RBA303" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.MaximumDurationInMinutes -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting duration is limited" `
        -Evidence @{ maximumDurationInMinutes = $RbaSettings.MaximumDurationInMinutes }

    Add-RbaFinding -Findings $findings -RuleId "RBA304" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring meetings are disabled" `
        -Evidence @{ allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings }

    Add-RbaFinding -Findings $findings -RuleId "RBA305" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "NotApplicable" } elseif ($RbaSettings.EnforceSchedulingHorizon) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring series beyond the booking window are declined" `
        -Evidence @{ enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon; bookingWindowInDays = $RbaSettings.BookingWindowInDays }

    Add-RbaFinding -Findings $findings -RuleId "RBA306" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "NotApplicable" } elseif (-not $RbaSettings.EnforceSchedulingHorizon) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring series are truncated at the booking window" `
        -Evidence @{ enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon; bookingWindowInDays = $RbaSettings.BookingWindowInDays }

    Add-RbaFinding -Findings $findings -RuleId "RBA307" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.ScheduleOnlyDuringWorkHours) { "Detected" } else { "NotDetected" }) `
        -Title "Bookings are restricted to resource work hours" `
        -Evidence @{ scheduleOnlyDuringWorkHours = $RbaSettings.ScheduleOnlyDuringWorkHours }

    Add-RbaFinding -Findings $findings -RuleId "RBA308" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AllowConflicts) { "Detected" } else { "NotDetected" }) `
        -Title "Conflicting requests are allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; conflictPercentageAllowed = $RbaSettings.ConflictPercentageAllowed; maximumConflictInstances = $RbaSettings.MaximumConflictInstances }

    $recurringConflictThresholdsApply = $settingsAvailable -and $RbaSettings.AllowRecurringMeetings -and
    -not $RbaSettings.AllowConflicts
    Add-RbaFinding -Findings $findings -RuleId "RBA309" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $recurringConflictThresholdsApply) { "NotApplicable" } elseif ($RbaSettings.ConflictPercentageAllowed -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A recurring-series conflict percentage is allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; conflictPercentageAllowed = $RbaSettings.ConflictPercentageAllowed }

    Add-RbaFinding -Findings $findings -RuleId "RBA310" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $recurringConflictThresholdsApply) { "NotApplicable" } elseif ($RbaSettings.MaximumConflictInstances -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A recurring-series conflict count is allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; maximumConflictInstances = $RbaSettings.MaximumConflictInstances }

    Add-RbaFinding -Findings $findings -RuleId "RBA311" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.ProcessExternalMeetingMessages) { "Detected" } else { "NotDetected" }) `
        -Title "External meeting messages are not processed" `
        -Evidence @{ processExternalMeetingMessages = $RbaSettings.ProcessExternalMeetingMessages }

    $isWorkspace = $mailboxAvailable -and $script:Mailbox.ResourceType -eq "Workspace"
    Add-RbaFinding -Findings $findings -RuleId "RBA500" -Severity Error `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif (-not $isWorkspace) { "NotApplicable" } elseif (-not $placeAvailable) { "NotEvaluated" } elseif ([string]::IsNullOrEmpty($script:Place.Capacity)) { "Detected" } else { "NotDetected" }) `
        -Title "Workspace capacity is missing" -Evidence $script:Place.Capacity

    $workspaceSettingsInvalid = $isWorkspace -and $settingsAvailable -and
    ($RbaSettings.EnforceCapacity -ne $true -or $RbaSettings.AllowConflicts -ne $true)
    Add-RbaFinding -Findings $findings -RuleId "RBA501" -Severity Error `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif (-not $isWorkspace) { "NotApplicable" } elseif (-not $settingsAvailable) { "NotEvaluated" } elseif ($workspaceSettingsInvalid) { "Detected" } else { "NotDetected" }) `
        -Title "Workspace calendar settings are incomplete" `
        -Evidence @{ enforceCapacity = $RbaSettings.EnforceCapacity; allowConflicts = $RbaSettings.AllowConflicts }

    Add-RbaFinding -Findings $findings -RuleId "RBA510" -Severity Warning `
        -Status $(if (-not $placeAvailable) { "NotEvaluated" } elseif ([string]::IsNullOrEmpty($script:Place.Localities)) { "Detected" } else { "NotDetected" }) `
        -Title "Resource is not in a room list" -Evidence @{ roomListCount = @($script:Place.Localities).Count }

    $missingPlaceProperties = if ($placeAvailable) {
        @(@("City", "Floor", "Capacity") | Where-Object { [string]::IsNullOrEmpty($script:Place.$_) })
    } else { @() }
    Add-RbaFinding -Findings $findings -RuleId "RBA511" -Severity Warning `
        -Status $(if (-not $placeAvailable) { "NotEvaluated" } elseif ($missingPlaceProperties.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Room finder properties are missing" -Evidence @{ properties = $missingPlaceProperties }

    $delegateCount = @($RbaSettings.ResourceDelegates).Count
    $requestOutOfPolicyCount = @($RbaSettings.RequestOutOfPolicy).Count
    $bookInPolicyCount = @($RbaSettings.BookInPolicy).Count
    $noDelegates = $settingsAvailable -and $delegateCount -eq 0
    $noDelegateRouteRequired = $noDelegates -and $RbaSettings.AllBookInPolicy -eq $true -and
    $RbaSettings.AllRequestOutOfPolicy -eq $false -and $requestOutOfPolicyCount -eq 0
    Add-RbaFinding -Findings $findings -RuleId "RBA400" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($noDelegateRouteRequired) { "Detected" } else { "NotApplicable" }) `
        -Title "No delegates are required by the configured request routes" `
        -Evidence @{ delegateCount = $delegateCount; allBookInPolicy = $RbaSettings.AllBookInPolicy; allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA401" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($RbaSettings.ForwardRequestsToDelegates -and -not $RbaSettings.AllBookInPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "Forwarding is enabled without delegates for in-policy requests" `
        -Evidence @{ delegateCount = $delegateCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; allBookInPolicy = $RbaSettings.AllBookInPolicy }

    Add-RbaFinding -Findings $findings -RuleId "RBA402" -Severity Error `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Out-of-policy requesters are configured without delegates" -Evidence @{ requesterCount = $requestOutOfPolicyCount; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA403" -Severity Error `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($RbaSettings.AllRequestOutOfPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All out-of-policy requests are enabled without delegates" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA600" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.DeleteComments) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting body deletion can remove Teams information" -Evidence $RbaSettings.DeleteComments

    Add-RbaFinding -Findings $findings -RuleId "RBA601" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.RemovePrivateProperty) { "Detected" } else { "NotDetected" }) `
        -Title "The private flag is cleared from incoming meetings" `
        -Evidence @{ removePrivateProperty = $RbaSettings.RemovePrivateProperty }

    Add-RbaFinding -Findings $findings -RuleId "RBA602" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.DeleteSubject) { "Detected" } else { "NotDetected" }) `
        -Title "The original meeting subject is removed" `
        -Evidence @{ deleteSubject = $RbaSettings.DeleteSubject; addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject }

    Add-RbaFinding -Findings $findings -RuleId "RBA603" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AddOrganizerToSubject) { "Detected" } else { "NotDetected" }) `
        -Title "The organizer name replaces the meeting subject" `
        -Evidence @{ addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject; deleteSubject = $RbaSettings.DeleteSubject }

    Add-RbaFinding -Findings $findings -RuleId "RBA604" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.RemoveCanceledMeetings) { "Detected" } else { "NotDetected" }) `
        -Title "Canceled meetings are retained on the resource calendar" `
        -Evidence @{ removeCanceledMeetings = $RbaSettings.RemoveCanceledMeetings }

    $skippedExternalCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false.").Count
    } else { 0 }
    Add-RbaFinding -Findings $findings -RuleId "RBA700" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($skippedExternalCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "External meeting requests were skipped" -Evidence @{ count = $skippedExternalCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA410" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0) { "NotApplicable" } elseif (-not $RbaSettings.AddNewRequestsTentatively) { "Detected" } else { "NotDetected" }) `
        -Title "New requests are not added tentatively for delegate review" `
        -Evidence @{ addNewRequestsTentatively = $RbaSettings.AddNewRequestsTentatively; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA411" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0 -or -not $RbaSettings.ForwardRequestsToDelegates) { "NotApplicable" } elseif ($RbaSettings.AllBookInPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All in-policy requests auto-book without delegate review" `
        -Evidence @{ allBookInPolicy = $RbaSettings.AllBookInPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA412" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0 -or -not $RbaSettings.ForwardRequestsToDelegates -or $RbaSettings.AllBookInPolicy) { "NotApplicable" } elseif ($bookInPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "BookInPolicy users auto-book without delegate review" `
        -Evidence @{ bookInPolicyCount = $bookInPolicyCount; allBookInPolicy = $RbaSettings.AllBookInPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    $delegateRoutingApplies = $settingsAvailable -and $delegateCount -gt 0 -and $RbaSettings.ForwardRequestsToDelegates
    Add-RbaFinding -Findings $findings -RuleId "RBA420" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies) { "NotApplicable" } elseif (-not $RbaSettings.AllRequestOutOfPolicy -and $requestOutOfPolicyCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No out-of-policy requests can be routed to delegates" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA421" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies -or $RbaSettings.AllRequestOutOfPolicy) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Out-of-policy delegate referrals are limited to listed requesters" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA422" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies) { "NotApplicable" } elseif ($RbaSettings.AllRequestOutOfPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All users can submit out-of-policy requests for delegate review" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA423" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllRequestOutOfPolicy) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "AllRequestOutOfPolicy overrides the requester list" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount }

    $logEntryCount = @($script:RBALog).Count
    $processedActionCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Action:Accept|Action:Decline|Action:Tentative").Count
    } else { 0 }
    $updatedCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest").Count
    } else { 0 }
    Add-RbaFinding -Findings $findings -RuleId "RBA701" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "Detected" } else { "NotDetected" }) `
        -Title "No usable RBA log history was found" -Evidence @{ entryCount = $logEntryCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA702" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "NotApplicable" } elseif ($processedActionCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No meeting actions were found in the RBA log" `
        -Evidence @{ entryCount = $logEntryCount; processedActionCount = $processedActionCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA703" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "NotApplicable" } elseif ($updatedCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No meeting updates were found in the RBA log" `
        -Evidence @{ entryCount = $logEntryCount; updatedCount = $updatedCount }

    $recurrenceHorizonDeclineCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Recurrence ends is past the booking window. Meeting will be declined.").Count
    } else { 0 }
    Add-RbaFinding -Findings $findings -RuleId "RBA704" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($recurrenceHorizonDeclineCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring requests exceeded the booking window and were declined" `
        -Evidence @{ count = $recurrenceHorizonDeclineCount }

    $recurrenceTruncationCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Truncating meeting recurrence end window").Count
    } else { 0 }
    Add-RbaFinding -Findings $findings -RuleId "RBA705" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($recurrenceTruncationCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring requests were truncated at the booking window" `
        -Evidence @{ count = $recurrenceTruncationCount }

    $meetingSearchRequested = -not [string]::IsNullOrWhiteSpace($MeetingSubject)
    $meetingSearchStatus = $script:MeetingLogSearch.status
    Add-RbaFinding -Findings $findings -RuleId "RBA710" -Severity Warning `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -eq "NotFound") { "Detected" } else { "NotDetected" }) `
        -Title "Meeting subject was not found in the retained RBA log" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA711" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -in @("Found", "FoundWithoutMeetingId")) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting subject was found in the retained RBA log" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount; meetingIdCount = @($script:MeetingLogSearch.meetingIds).Count; eventCount = $script:MeetingLogSearch.eventCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA712" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.updateCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting updates were found in targeted RBA log events" `
        -Evidence @{ updateCount = $script:MeetingLogSearch.updateCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA713" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.cancellationCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting cancellations were found in targeted RBA log events" `
        -Evidence @{ cancellationCount = $script:MeetingLogSearch.cancellationCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA714" -Severity Warning `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -eq "FoundWithoutMeetingId") { "Detected" } else { "NotDetected" }) `
        -Title "Meeting subject matched but no meeting ID was extracted" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount }

    Add-RbaFinding -Findings $findings -RuleId "RBA715" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.declineCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Decline actions were found in targeted RBA log events" `
        -Evidence @{ declineCount = $script:MeetingLogSearch.declineCount; horizonDeclineCount = $script:MeetingLogSearch.horizonDeclineCount }

    $defaultCalendarPermission = @($script:CalendarFolderPermissions | Where-Object {
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -eq "default"
        } | Select-Object -First 1)
    $defaultAccessRights = if ($defaultCalendarPermission.Count -gt 0) {
        @($defaultCalendarPermission[0].AccessRights | ForEach-Object { [string]$_ })
    } else { @() }
    Add-RbaFinding -Findings $findings -RuleId "RBA801" -Severity Information `
        -Status $(if (-not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Default Calendar folder visibility" `
        -Evidence @{ present = $defaultCalendarPermission.Count -gt 0; accessRights = $defaultAccessRights }

    $ownerPermissions = @($script:CalendarFolderPermissions | Where-Object {
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "Owner"
        })
    Add-RbaFinding -Findings $findings -RuleId "RBA802" -Severity Warning `
        -Status $(if (-not $calendarPermissionsAvailable) { "NotEvaluated" } elseif ($ownerPermissions.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Owner access is assigned on the resource Calendar folder" `
        -Evidence @{ ownerPermissionCount = $ownerPermissions.Count }

    $directCalendarEditorIdentities = @($script:CalendarFolderPermissions | Where-Object {
            $rights = @($_.AccessRights | ForEach-Object { [string]$_ })
            $rights -contains "Editor" -or $rights -contains "Owner"
        } | ForEach-Object { Get-RbaPermissionIdentity -PermissionUser $_.User })
    $configuredDelegateCount = if ($settingsAvailable) {
        @($script:RbaSettings.ResourceDelegates).Count
    } else { 0 }
    $delegatesWithoutDirectCalendarAccess = if ($settingsAvailable -and $calendarPermissionsAvailable -and
        $script:ResourceDelegateIdentitySetsAvailable) {
        @($script:ResourceDelegateIdentitySets | Where-Object {
                @($_.aliases | Where-Object { $_ -in $directCalendarEditorIdentities }).Count -eq 0
            })
    } else { @() }
    Add-RbaFinding -Findings $findings -RuleId "RBA803" -Severity Warning `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable -or -not $script:ResourceDelegateIdentitySetsAvailable) { "NotEvaluated" } elseif ($configuredDelegateCount -eq 0) { "NotApplicable" } elseif ($delegatesWithoutDirectCalendarAccess.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A resource delegate has no matching direct Calendar Editor permission" `
        -Evidence @{ configuredDelegateCount = $configuredDelegateCount; unmatchedIdentityCount = $delegatesWithoutDirectCalendarAccess.Count }

    Add-RbaFinding -Findings $findings -RuleId "RBA804" -Severity Information `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Calendar visibility and subject post-processing are separate controls" `
        -Evidence @{ defaultAccessRights = $defaultAccessRights; deleteSubject = $RbaSettings.DeleteSubject; addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject; relatedRuleIds = @("RBA602", "RBA603") }

    Add-RbaFinding -Findings $findings -RuleId "RBA805" -Severity Information `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Calendar visibility and private-property removal are separate controls" `
        -Evidence @{ defaultAccessRights = $defaultAccessRights; removePrivateProperty = $RbaSettings.RemovePrivateProperty; relatedRuleIds = @("RBA601") }

    $explicitFullAccessPermissions = @($script:MailboxPermissions | Where-Object {
            -not $_.IsInherited -and -not $_.Deny -and
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "FullAccess" -and
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -notin @("nt authority\self", "self")
        })
    Add-RbaFinding -Findings $findings -RuleId "RBA820" -Severity Warning `
        -Status $(if (-not $mailboxPermissionsAvailable) { "NotEvaluated" } elseif ($explicitFullAccessPermissions.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Explicit Full Access is assigned on the resource mailbox" `
        -Evidence @{ explicitFullAccessCount = $explicitFullAccessPermissions.Count }

    return $findings
}

function ConvertTo-RbaIdentityList {
    param(
        [AllowNull()]
        [object[]]$Value
    )

    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        $result.Add((Get-RbaSanitizedIdentity -Value $item -PreserveTargetIdentity))
    }
    return $result.ToArray()
}

function Get-RbaSanitizedIdentity {
    param(
        [AllowNull()]
        [object]$Value,

        [switch]$PreserveTargetIdentity
    )

    $identityText = [string]$Value
    if ($IncludeSensitiveData) {
        return $identityText
    }

    $normalizedIdentity = $identityText.Trim().ToLowerInvariant()
    if ($PreserveTargetIdentity -and $normalizedIdentity -eq $Identity.Trim().ToLowerInvariant()) {
        return $identityText
    }

    if (-not [string]::IsNullOrEmpty($normalizedIdentity) -and
        $script:SanitizedIdentityMap.ContainsKey($normalizedIdentity)) {
        return $script:SanitizedIdentityMap[$normalizedIdentity]
    }

    $script:SanitizedIdentitySequence++
    $sanitizedIdentity = "SanitizedIdentity-$($script:SanitizedIdentitySequence)"
    if (-not [string]::IsNullOrEmpty($normalizedIdentity)) {
        $script:SanitizedIdentityMap.Add($normalizedIdentity, $sanitizedIdentity)
    }
    # An identity without a stable key receives a unique placeholder for each occurrence.
    return $sanitizedIdentity
}

function Get-RbaMailboxIdentitySummaryObject {
    if ($script:collectorStatuses["Mailbox"].status -ne "Success") {
        return $null
    }

    $primarySmtpAddress = [string]$script:Mailbox.PrimarySmtpAddress
    $emailAddresses = @($script:Mailbox.EmailAddresses | ForEach-Object { [string]$_ })
    $normalizedInput = $Identity.Trim()
    $proxyAddressMatch = @($emailAddresses | Where-Object {
            ($_ -replace '^(?i)smtp:', '') -ieq $normalizedInput
        }).Count -gt 0
    $inputIdentityMatch = if (-not [string]::IsNullOrWhiteSpace($primarySmtpAddress) -and
        $primarySmtpAddress -ieq $normalizedInput) {
        "PrimarySmtpAddress"
    } elseif ($proxyAddressMatch) {
        "ProxyAddress"
    } else {
        "OtherResolvedIdentity"
    }

    return [PSCustomObject]@{
        objectState         = $script:MailboxObjectState
        displayName         = [string]$script:Mailbox.DisplayName
        alias               = [string]$script:Mailbox.Alias
        primarySmtpAddress  = $primarySmtpAddress
        inputIdentityMatch  = $inputIdentityMatch
        emailAddressCount   = $emailAddresses.Count
        whenCreatedUtc      = $(if ($null -ne $script:Mailbox.WhenCreatedUTC) { ([DateTime]$script:Mailbox.WhenCreatedUTC).ToUniversalTime().ToString("o") } else { $null })
        whenChangedUtc      = $(if ($null -ne $script:Mailbox.WhenChangedUTC) { ([DateTime]$script:Mailbox.WhenChangedUTC).ToUniversalTime().ToString("o") } else { $null })
        emailAddresses      = $emailAddresses
        exchangeGuid        = [string]$script:Mailbox.ExchangeGuid
        externalDirectoryId = [string]$script:Mailbox.ExternalDirectoryObjectId
    }
}

function Get-RbaLogSummaryObject {
    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        return $null
    }

    $starts = @($script:RBALog | Select-String -Pattern "START -")
    return [PSCustomObject]@{
        entryCount              = @($script:RBALog).Count
        processedEventCount     = $starts.Count
        acceptedCount           = @($script:RBALog | Select-String -Pattern "Action:Accept").Count
        declinedCount           = @($script:RBALog | Select-String -Pattern "Action:Decline").Count
        tentativeCount          = @($script:RBALog | Select-String -Pattern "Action:Tentative").Count
        updatedCount            = @($script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest").Count
        cancellationCount       = @($script:RBALog | Select-String -Pattern "It's a meeting cancellation.").Count
        delegateReferralCount   = @($script:RBALog | Select-String -Pattern "Forwarding Request To Delegates").Count
        skippedExternalCount    = @($script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false.").Count
        horizonDeclineCount     = @($script:RBALog | Select-String -Pattern "Recurrence ends is past the booking window. Meeting will be declined.").Count
        recurrenceTruncateCount = @($script:RBALog | Select-String -Pattern "Truncating meeting recurrence end window").Count
    }
}

function Get-RbaCalendarPermissionSummaryObject {
    if ($script:collectorStatuses["CalendarFolderPermissions"].status -ne "Success") {
        return $null
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($permission in @($script:CalendarFolderPermissions)) {
        $permissionIdentity = Get-RbaPermissionIdentity -PermissionUser $permission.User
        $principal = if ($permissionIdentity.Trim() -in @("default", "anonymous") -or $IncludeSensitiveData) {
            [string]$permission.User
        } else {
            Get-RbaSanitizedIdentity -Value $permissionIdentity
        }
        $entries.Add([PSCustomObject]@{
                principal              = $principal
                accessRights           = @($permission.AccessRights | ForEach-Object { [string]$_ })
                sharingPermissionFlags = @($permission.SharingPermissionFlags | ForEach-Object { [string]$_ })
            })
    }

    return [PSCustomObject]@{
        entryCount = $entries.Count
        entries    = $entries.ToArray()
    }
}

function Get-RbaMailboxPermissionSummaryObject {
    if ($script:collectorStatuses["MailboxPermissions"].status -ne "Success") {
        return $null
    }

    $fullAccessPermissions = @($script:MailboxPermissions | Where-Object {
            -not $_.IsInherited -and -not $_.Deny -and
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "FullAccess" -and
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -notin @("nt authority\self", "self")
        })
    $grantees = @($fullAccessPermissions | ForEach-Object {
            if ($IncludeSensitiveData) {
                [string]$_.User
            } else {
                Get-RbaSanitizedIdentity -Value (Get-RbaPermissionIdentity -PermissionUser $_.User)
            }
        })

    return [PSCustomObject]@{
        explicitFullAccessCount = $fullAccessPermissions.Count
        grantees                = $grantees
    }
}

function Write-RbaJson {
    $successfulCollectors = @($script:collectorStatuses.Values | Where-Object { $_.status -eq "Success" }).Count
    $collectionStatus = if ($successfulCollectors -eq $script:collectorStatuses.Count) {
        "Complete"
    } elseif ($successfulCollectors -eq 0) {
        "Failed"
    } else {
        "Partial"
    }

    $inboxRules = if ($script:collectorStatuses["InboxRules"].status -eq "Success") {
        [PSCustomObject]@{
            totalCount        = @($script:InboxRules).Count
            delegateRuleCount = @($script:InboxRules | Where-Object { $_.Name -like "Delegate Rule*" }).Count
            redactedCount     = @($script:InboxRules | Where-Object { $_.Name -like "REDACTED-*" }).Count
        }
    } else { $null }
    if ($IncludeSensitiveData -and $null -ne $inboxRules) {
        $inboxRules | Add-Member -MemberType NoteProperty -Name ruleNames -Value @($script:InboxRules.Name)
    }

    $calendarProcessing = if ($script:collectorStatuses["CalendarProcessing"].status -eq "Success") {
        [PSCustomObject]@{
            automateProcessing                  = $RbaSettings.AutomateProcessing
            allowConflicts                      = $RbaSettings.AllowConflicts
            allowDistributionGroup              = $RbaSettings.AllowDistributionGroup
            allowMultipleResources              = $RbaSettings.AllowMultipleResources
            maximumDurationInMinutes            = $RbaSettings.MaximumDurationInMinutes
            minimumDurationInMinutes            = $RbaSettings.MinimumDurationInMinutes
            allowRecurringMeetings              = $RbaSettings.AllowRecurringMeetings
            scheduleOnlyDuringWorkHours         = $RbaSettings.ScheduleOnlyDuringWorkHours
            processExternalMeetingMessages      = $RbaSettings.ProcessExternalMeetingMessages
            bookingWindowInDays                 = $RbaSettings.BookingWindowInDays
            conflictPercentageAllowed           = $RbaSettings.ConflictPercentageAllowed
            maximumConflictInstances            = $RbaSettings.MaximumConflictInstances
            maximumConflictPercentage           = $RbaSettings.MaximumConflictPercentage
            enforceSchedulingHorizon            = $RbaSettings.EnforceSchedulingHorizon
            enforceCapacity                     = $RbaSettings.EnforceCapacity
            requestOutOfPolicy                  = ConvertTo-RbaIdentityList -Value $RbaSettings.RequestOutOfPolicy
            allRequestOutOfPolicy               = $RbaSettings.AllRequestOutOfPolicy
            bookInPolicy                        = ConvertTo-RbaIdentityList -Value $RbaSettings.BookInPolicy
            allBookInPolicy                     = $RbaSettings.AllBookInPolicy
            requestInPolicy                     = ConvertTo-RbaIdentityList -Value $RbaSettings.RequestInPolicy
            allRequestInPolicy                  = $RbaSettings.AllRequestInPolicy
            resourceDelegates                   = ConvertTo-RbaIdentityList -Value $RbaSettings.ResourceDelegates
            addNewRequestsTentatively           = $RbaSettings.AddNewRequestsTentatively
            forwardRequestsToDelegates          = $RbaSettings.ForwardRequestsToDelegates
            addOrganizerToSubject               = $RbaSettings.AddOrganizerToSubject
            deleteSubject                       = $RbaSettings.DeleteSubject
            deleteComments                      = $RbaSettings.DeleteComments
            deleteAttachments                   = $RbaSettings.DeleteAttachments
            removePrivateProperty               = $RbaSettings.RemovePrivateProperty
            deleteNonCalendarItems              = $RbaSettings.DeleteNonCalendarItems
            removeForwardedMeetingNotifications = $RbaSettings.RemoveForwardedMeetingNotifications
            removeCanceledMeetings              = $RbaSettings.RemoveCanceledMeetings
            enableAutoRelease                   = $RbaSettings.EnableAutoRelease
            addAdditionalResponse               = $RbaSettings.AddAdditionalResponse
        }
    } else { $null }
    if ($IncludeSensitiveData -and $null -ne $calendarProcessing) {
        $calendarProcessing | Add-Member -MemberType NoteProperty -Name additionalResponse -Value $RbaSettings.AdditionalResponse
    }

    $mailboxIdentitySummary = Get-RbaMailboxIdentitySummaryObject
    $mailboxSummary = if ($null -ne $mailboxIdentitySummary) {
        $summary = [PSCustomObject]@{
            identity             = $Identity
            recipientTypeDetails = $script:Mailbox.RecipientTypeDetails
            resourceType         = $script:Mailbox.ResourceType
            objectState          = $mailboxIdentitySummary.objectState
            displayName          = $mailboxIdentitySummary.displayName
            alias                = $mailboxIdentitySummary.alias
            primarySmtpAddress   = $mailboxIdentitySummary.primarySmtpAddress
            inputIdentityMatch   = $mailboxIdentitySummary.inputIdentityMatch
            emailAddressCount    = $mailboxIdentitySummary.emailAddressCount
            whenCreatedUtc       = $mailboxIdentitySummary.whenCreatedUtc
            whenChangedUtc       = $mailboxIdentitySummary.whenChangedUtc
        }
        if ($IncludeSensitiveData) {
            $summary | Add-Member -MemberType NoteProperty -Name emailAddresses -Value $mailboxIdentitySummary.emailAddresses
            $summary | Add-Member -MemberType NoteProperty -Name exchangeGuid -Value $mailboxIdentitySummary.exchangeGuid
            $summary | Add-Member -MemberType NoteProperty -Name externalDirectoryId -Value $mailboxIdentitySummary.externalDirectoryId
        }
        $summary
    } else { $null }

    $script:MeetingLogSearch = Get-RbaMeetingLogSearchObject

    $data = [ordered]@{
        metadata            = [ordered]@{
            schemaVersion    = "1.0-preview"
            scriptVersion    = $BuildVersion
            collectedAtUtc   = (Get-Date).ToUniversalTime().ToString("o")
            identity         = $Identity
            collectionStatus = $collectionStatus
            privacyMode      = $(if ($IncludeSensitiveData) { "Full" } elseif (-not [string]::IsNullOrWhiteSpace($MeetingSubject)) { "TargetedMeeting" } else { "Sanitized" })
        }
        collectors          = $script:collectorStatuses
        mailbox             = $mailboxSummary
        place               = $(if ($script:collectorStatuses["Place"].status -eq "Success") {
                [PSCustomObject]@{
                    city          = $script:Place.City
                    floor         = $script:Place.Floor
                    capacity      = $script:Place.Capacity
                    roomListCount = @($script:Place.Localities).Count
                }
            } else { $null })
        calendarProcessing  = $calendarProcessing
        calendarPermissions = Get-RbaCalendarPermissionSummaryObject
        mailboxPermissions  = Get-RbaMailboxPermissionSummaryObject
        inboxRules          = $inboxRules
        rbaLogSummary       = Get-RbaLogSummaryObject
        meetingLogSearch    = $script:MeetingLogSearch
        findings            = @(Get-RbaFindings)
        collectionErrors    = @($script:collectionErrors)
        evaluationErrors    = @($script:evaluationErrors)
    }

    if ($IncludeSensitiveData) {
        if ($null -ne $data.place) {
            $data.place | Add-Member -MemberType NoteProperty -Name roomLists -Value @($script:Place.Localities)
        }
        $data.fullRbaLog = @($script:RBALog)
        if (Test-Path -Path $SummaryFilename) {
            $data.transcript = Get-Content -Path $SummaryFilename -Raw
        }
    }

    $json = $data | ConvertTo-Json -Depth 8 -ErrorAction Stop
    Set-Content -Path $JsonFilename -Value $json -Encoding utf8 -ErrorAction Stop
}

try {
    # Attempt every independent collector before running dependent evaluations.
    Invoke-RbaCollectorOperation -Name "Mailbox" -Action { CollectMailbox }
    Invoke-RbaCollectorOperation -Name "Place" -Action { CollectPlace }
    Invoke-RbaCollectorOperation -Name "InboxRules" -Action { ValidateInboxRules }
    Invoke-RbaCollectorOperation -Name "CalendarProcessing" -Action { GetCalendarProcessing }
    Invoke-RbaCollectorOperation -Name "CalendarFolderPermissions" -Action { CollectCalendarFolderPermissions }
    Invoke-RbaCollectorOperation -Name "MailboxPermissions" -Action { CollectMailboxPermissions }
    Invoke-RbaCollectorOperation -Name "RbaLog" -Action { CollectRBALog }

    if ($script:collectorStatuses["CalendarProcessing"].status -eq "Success") {
        Invoke-RbaEvaluation -Name "Resource delegate identity enrichment" -Action { Initialize-RbaResourceDelegateIdentitySets }
        Invoke-RbaEvaluation -Name "Calendar processing" -Action { EvaluateCalProcessing }
        if ($script:collectorStatuses["Mailbox"].status -eq "Success" -and
            (-not $script:Workspace -or $script:collectorStatuses["Place"].status -eq "Success")) {
            Invoke-RbaEvaluation -Name "Workspace" -Action { ValidateWorkspace }
        }
        ProcessingLogic
        Invoke-RbaEvaluation -Name "Policy criteria" -Action { RBACriteria }
        Invoke-RbaEvaluation -Name "Processing routes" -Action { RBAProcessingValidation }
        Invoke-RbaEvaluation -Name "In-policy processing" -Action { InPolicyProcessing }
        Invoke-RbaEvaluation -Name "Out-of-policy processing" -Action { OutOfPolicyProcessing }
        Invoke-RbaEvaluation -Name "Delegate settings" -Action { RBADelegateSettings }
        Invoke-RbaEvaluation -Name "Post-processing" -Action { RBAPostProcessing; VerbosePostProcessing }
    } else {
        Write-Warning "Calendar processing evaluations were skipped because required evidence is unavailable."
    }

    if ($script:collectorStatuses["Place"].status -eq "Success") {
        Invoke-RbaEvaluation -Name "Room list settings" -Action { ValidateRoomListSettings }
    } else {
        Write-Warning "Place evaluations were skipped because required evidence is unavailable."
    }

    Invoke-RbaEvaluation -Name "RBA log summary" -Action { RBALogSummary }
} catch {
    $errorInfo = ConvertTo-RbaErrorInfo -ErrorRecord $_
    $script:evaluationErrors.Add([PSCustomObject]@{
            evaluation            = "Unhandled script operation"
            message               = $errorInfo.message
            exceptionType         = $errorInfo.exceptionType
            category              = $errorInfo.category
            fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
            innerExceptionMessage = $errorInfo.innerExceptionMessage
        })
    Write-Warning "An unexpected reporting error occurred: $($errorInfo.message)"
} finally {
    if ($script:TranscriptStarted) {
        Stop-Transcript | Out-Null
        $script:TranscriptStarted = $false
    }
}

try {
    Write-RbaJson
    Write-Host "`r`nRBA JSON Output saved as [" -NoNewline
    Write-Host -ForegroundColor Cyan $JsonFilename -NoNewline
    Write-Host "] in the current directory."
} catch {
    $errorInfo = ConvertTo-RbaErrorInfo -ErrorRecord $_
    Write-Warning "Unable to write RBA JSON output '$JsonFilename': $($errorInfo.message)"
}

$skillUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/EXO-RBA-Troubleshooting-SKILL.md"
Write-Host "Tenant admins can install and use the EXO RBA troubleshooting skill for deeper analysis:"
Write-Host -ForegroundColor Cyan $skillUrl
