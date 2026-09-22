# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-RbaCollector {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action,

        [switch]$AllowEmptyCollection,

        [string]$FailureMessage
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
        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
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
        if ([string]::IsNullOrWhiteSpace($FailureMessage)) {
            Write-Warning "$Name collection failed: $($errorInfo.message)"
        } else {
            Write-Warning $FailureMessage
        }
        return $null
    }
}

function Get-RbaMailboxData {
    Write-Host -ForegroundColor Cyan "Running: Get-Mailbox -Identity $Identity"
    $script:Mailbox = Invoke-RbaCollector -Name "Mailbox" -Action {
        try {
            $mailbox = Get-Mailbox -Identity $Identity -ErrorAction Stop
            if ($null -eq $mailbox) {
                throw "Active mailbox lookup returned null."
            }
            $script:MailboxObjectState = "Active"
            return $mailbox
        } catch {
            $activeLookupError = $_
            Write-Verbose -Message "Active mailbox lookup failed. Checking for a recoverable soft-deleted mailbox."
            try {
                $mailbox = Get-Mailbox -Identity $Identity -SoftDeletedMailbox -ErrorAction Stop
            } catch {
                $fallbackErrorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
                Write-Verbose -Message "Soft-deleted mailbox lookup failed: $($fallbackErrorInfo.message) (Category: $($fallbackErrorInfo.category); fully qualified error ID: $($fallbackErrorInfo.fullyQualifiedErrorId))."
                throw $activeLookupError
            }
            if ($null -eq $mailbox) {
                Write-Verbose -Message "Soft-deleted mailbox lookup returned null."
                throw $activeLookupError
            }
            $script:MailboxObjectState = "SoftDeleted"
            return $mailbox
        }
    }

    # check we get a response
    if ($null -eq $script:Mailbox) {
        Write-Host -ForegroundColor Red "Get-Mailbox was unavailable. Make sure you Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline."
    } else {
        if ($script:MailboxObjectState -eq "SoftDeleted") {
            Write-Host -ForegroundColor Red "The resource mailbox is soft-deleted and cannot perform active RBA processing."
        } elseif ($script:Mailbox.RecipientTypeDetails -ne "RoomMailbox" -and $script:Mailbox.RecipientTypeDetails -ne "EquipmentMailbox") {
            Write-Host -ForegroundColor Red "The mailbox is not a Room Mailbox / Equipment Mailbox. RBA will only work with these. Stopping."
        }
        if ($script:Mailbox.ResourceType -eq "Workspace") {
            $script:Workspace = $true
        }
        if ($script:Mailbox.RecipientTypeDetails -eq "RoomMailbox" -or $script:Mailbox.RecipientTypeDetails -eq "EquipmentMailbox") {
            Write-Host -ForegroundColor Green "The mailbox is valid for RBA to work with."
        }
    }
}

function Get-RbaPlaceData {
    # Get-Place does not cross forest boundaries so we will get an error here if we are not in the right forest.
    Write-Host -ForegroundColor Cyan "Running: Get-Place -Identity $Identity"
    $placeFailureMessage = "Get-Place failed to get information from $Identity. Double-check the setup of the room."
    $script:Place = Invoke-RbaCollector -Name "Place" -FailureMessage $placeFailureMessage -Action {
        $placeOutput = @(Get-Place -Identity $Identity -ErrorAction Stop *>&1)
        $placeError = @($placeOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Select-Object -First 1)
        if ($placeError.Count -gt 0) { throw $placeError[0] }

        $placeObjects = @($placeOutput | Where-Object {
                $_ -isnot [System.Management.Automation.InformationRecord] -and
                $_ -isnot [System.Management.Automation.WarningRecord] -and
                $_ -isnot [System.Management.Automation.VerboseRecord] -and
                $_ -isnot [System.Management.Automation.DebugRecord]
            })
        if ($placeObjects.Count -eq 0) { throw "Get-Place returned no place objects." }
        if ($placeObjects.Count -gt 1) { Write-Verbose "Get-Place returned $($placeObjects.Count) results; using the first entry." }
        return $placeObjects[0]
    }

    if ($null -eq $script:Place) {
        Write-Host -ForegroundColor Red "Make sure you are running from the correct forest.  Get-Place does not cross forest boundaries."
        if ($null -ne $script:Mailbox -and $null -ne $script:Mailbox.Database) {
            Write-Host "Hint Forest is likely something like: [$($script:Mailbox.Database.split("DG")[0])]."
        }
    }

    Write-Host -ForegroundColor Yellow "For more information, see https://learn.microsoft.com/powershell/module/exchange/get-place"
    Write-Host
}

function Test-RbaInboxRules {
    Write-Host "Checking for Delegate Rules that will block RBA functionality..."
    Write-Host -ForegroundColor Cyan "Running: Get-InboxRule -Mailbox $Identity -IncludeHidden"
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
        Write-Host -ForegroundColor Yellow "To gain PII access, Mailbox is located on $($script:Mailbox.Database) on server $($script:Mailbox.ServerName)"
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

function Get-RbaCalendarProcessing {
    Write-Host -ForegroundColor Cyan "Running: Get-CalendarProcessing -Identity $Identity"
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

    Write-Host -ForegroundColor Green "Calendar processing settings collected successfully."
    Write-Host -ForegroundColor Yellow "For more information, see https://learn.microsoft.com/powershell/module/exchange/set-calendarprocessing"
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

function Get-RbaCalendarFolderPermissions {
    Write-Host -ForegroundColor Cyan "Running: Get-MailboxFolderPermission for the Calendar folder of $Identity"
    $failureMessage = "Unable to collect Calendar folder permissions for $Identity. Continuing with other available evidence."
    [array]$script:CalendarFolderPermissions = Invoke-RbaCollector -Name "CalendarFolderPermissions" -AllowEmptyCollection -FailureMessage $failureMessage -Action {
        Write-Verbose "Locating the Calendar folder for $Identity."
        # Materialize the remote result before selecting a folder. Select-Object -First can stop the
        # remote pipeline early and add a misleading "The pipeline has been stopped" transcript entry.
        $calendarFolders = @(Get-MailboxFolderStatistics -Identity $Identity -FolderScope Calendar -ErrorAction Stop)
        $calendarFolder = @($calendarFolders | Where-Object { $_.FolderType -eq "Calendar" })[0]
        if ($null -eq $calendarFolder) {
            throw "The Calendar folder could not be located."
        }

        $calendarFolderIdentity = "$Identity`:\$($calendarFolder.Name)"
        Write-Verbose "Collecting permissions from $calendarFolderIdentity."
        @(Get-MailboxFolderPermission -Identity $calendarFolderIdentity -ErrorAction Stop)
    }
    if ($script:collectorStatuses["CalendarFolderPermissions"].status -eq "Success") {
        Write-Host -ForegroundColor Green "Calendar folder permissions collected successfully."
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

function Get-RbaMailboxPermissions {
    Write-Host -ForegroundColor Cyan "Running: Get-MailboxPermission -Identity $Identity"
    [array]$script:MailboxPermissions = Invoke-RbaCollector -Name "MailboxPermissions" -AllowEmptyCollection -Action {
        @(Get-MailboxPermission -Identity $Identity -ErrorAction Stop)
    }
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

        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
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
