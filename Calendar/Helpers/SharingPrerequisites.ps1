# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Mailbox and selected owner-calendar prerequisites.

function Register-SharingFatalPrerequisiteFailure {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("SHR100", "SHR101", "SHR110", "SHR123", "SHR200", "SHR201")]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }

    $boundedReason = ($Reason -replace '[\r\n\t]+', ' ').Trim()
    if ($boundedReason.Length -gt 256) {
        $boundedReason = $boundedReason.Substring(0, 256)
    }
    $script:FatalPrerequisiteFailure = [PSCustomObject]@{
        ruleId = $RuleId
        reason = $boundedReason
    }
}

function Test-SharingMailboxNamePrerequisite {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Owner", "Receiver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [object]$Mailbox
    )

    $redactedProperty = @("DisplayName", "Name", "Alias") |
        ForEach-Object {
            $property = $Mailbox.PSObject.Properties[$_]
            if (($null -ne $property) -and
                (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) -and
                ([string]$property.Value -match "^\s*REDACTED-")) {
                [PSCustomObject]@{
                    Name  = $property.Name
                    Value = [string]$property.Value
                }
            }
        } |
        Select-Object -First 1
    if ($null -eq $redactedProperty) {
        return $true
    }

    $ruleId = if ($Role -eq "Owner") { "SHR101" } else { "SHR201" }
    $database = [string]$Mailbox.Database
    $databaseGuidance = if ([string]::IsNullOrWhiteSpace($database)) {
        ""
    } else {
        " for mailbox database [$database]"
    }
    $reason = "$Role mailbox name is redacted."
    Write-Host -ForegroundColor Red "$reason Obtain PII access$databaseGuidance and rerun."
    Add-SharingFinding -RuleId $ruleId -Status Detected -Area "$Role mailbox prerequisite" -Evidence @{
        mailboxRole   = $Role
        fieldName     = $redactedProperty.Name
        piiAvailable  = $false
        redactedValue = $redactedProperty.Value
        database      = $database
    }
    Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
    return $false
}

function Resolve-SharingMailboxPrerequisite {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Owner", "Receiver")]
        [string]$Role,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    $collectorName = "${Role}Mailbox"
    $ruleId = if ($Role -eq "Owner") { "SHR100" } else { "SHR200" }
    $cachedMailbox = if ($Role -eq "Owner") { $script:OwnerMB } else { $script:ReceiverMB }
    if (($null -ne $cachedMailbox) -and
        ($script:CollectorStatuses[$collectorName].status -eq "Success")) {
        return Test-SharingMailboxNamePrerequisite -Role $Role -Mailbox $cachedMailbox
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-Mailbox -Identity $Identity"
    try {
        $mailbox = Invoke-SharingCollector -Name $collectorName -Action {
            Get-Mailbox -Identity $Identity -ErrorAction Stop
        } -AllowNull
    } catch {
        $reason = "$Role mailbox lookup failed; prerequisite evidence is unavailable."
        Write-Host -ForegroundColor Red $reason
        Add-SharingFinding -RuleId $ruleId -Status NotEvaluated -Area "$Role mailbox prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
        return $false
    }

    if ($null -eq $mailbox) {
        $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "NoData"; error = $null }
        $reason = "Get-Mailbox returned no $Role mailbox object."
        Write-Host -ForegroundColor Red $reason
        Add-SharingFinding -RuleId $ruleId -Status Detected -Area "$Role mailbox prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId $ruleId -Reason $reason
        return $false
    }

    if ($Role -eq "Owner") {
        $script:OwnerMB = $mailbox
    } else {
        $script:ReceiverMB = $mailbox
    }
    return Test-SharingMailboxNamePrerequisite -Role $Role -Mailbox $mailbox
}

function Resolve-SharingMailboxPrerequisites {
    Write-Host -ForegroundColor Cyan "`r`rPrerequisite mailbox resolution:"
    if (-not (Resolve-SharingMailboxPrerequisite -Role Owner -Identity $Owner)) {
        return $false
    }
    if (-not (Resolve-SharingMailboxPrerequisite -Role Receiver -Identity $Receiver)) {
        return $false
    }
    return $true
}

function Resolve-OwnerCalendarPrerequisite {
    if (($null -ne $script:OwnerSelectedCalendar) -and
        ($null -ne $script:OwnerCalendarFolder) -and
        ($script:CollectorStatuses["OwnerFolderStatistics"].status -eq "Success") -and
        ($script:CollectorStatuses["OwnerCalendarFolder"].status -eq "Success")) {
        return $true
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar"
    try {
        $script:OwnerCalendarStats = @(Invoke-SharingCollector -Name "OwnerFolderStatistics" -Action {
                @(Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar -ErrorAction Stop)
            })
    } catch {
        $reason = "Owner calendar folder statistics are unavailable."
        Add-SharingFinding -RuleId "SHR110" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR110" -Reason $reason
        return $false
    }

    $ownerDefaultCalendarStats = @($script:OwnerCalendarStats |
            Where-Object -Property FolderType -EQ "Calendar")
    $ownerDefaultCalendarStat = if ($ownerDefaultCalendarStats.Count -eq 1) {
        $ownerDefaultCalendarStats[0]
    } else {
        $null
    }
    $script:OwnerCalendarRootName = $ownerDefaultCalendarStat.Name
    $matchingOwnerCalendarStats = @()
    if ($script:OwnerCalendarFolderPathSpecified -and
        ($null -ne $ownerDefaultCalendarStat)) {
        $requestedFolderIdentity = Get-CanonicalMailboxFolderIdentity `
            -Mailbox $Owner `
            -CalendarRootName $script:OwnerCalendarRootName `
            -FolderPath $script:NormalizedOwnerCalendarFolderPath
        $script:NormalizedOwnerCalendarFolderPath = $requestedFolderIdentity.Substring($requestedFolderIdentity.IndexOf(":") + 1)
        $matchingOwnerCalendarStats = @($script:OwnerCalendarStats | Where-Object -FilterScript {
                $statisticsFolderIdentity = Get-CanonicalMailboxFolderIdentity `
                    -Mailbox $Owner `
                    -CalendarRootName $script:OwnerCalendarRootName `
                    -FolderPath $_.FolderPath.ToString()
                $normalizedStatisticsPath = $statisticsFolderIdentity.Substring($statisticsFolderIdentity.IndexOf(":") + 1)
                [string]::Equals(
                    $normalizedStatisticsPath,
                    $script:NormalizedOwnerCalendarFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
        $ownerCalendarStat = if ($matchingOwnerCalendarStats.Count -eq 1) {
            $matchingOwnerCalendarStats[0]
        } else {
            $null
        }
    } else {
        $ownerCalendarStat = if ($script:OwnerCalendarFolderPathSpecified) {
            $null
        } else {
            $ownerDefaultCalendarStat
        }
    }

    if ($null -eq $ownerCalendarStat) {
        $script:CollectorStatuses["OwnerFolderStatistics"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        $selectionReason = if ($ownerDefaultCalendarStats.Count -gt 1) {
            "The default owner calendar folder selection matched more than one folder."
        } elseif (-not $script:OwnerCalendarFolderPathSpecified) {
            "The default owner calendar folder could not be identified."
        } elseif ($ownerDefaultCalendarStats.Count -eq 0) {
            "The default owner calendar root could not be identified for the requested path."
        } elseif ($matchingOwnerCalendarStats.Count -eq 0) {
            "The requested owner calendar folder path was not found."
        } else {
            "The requested owner calendar folder path matched more than one folder."
        }
        Write-Host -ForegroundColor Red "$selectionReason Requested owner-relative path: [$($script:NormalizedOwnerCalendarFolderPath)]."
        if ($script:OwnerCalendarStats.Count -gt 0) {
            Write-Host -ForegroundColor Yellow "Available Owner Calendar folders returned by Get-MailboxFolderStatistics:"
            $availableOwnerCalendarTable = $script:OwnerCalendarStats |
                Sort-Object -Property FolderPath |
                Format-Table -AutoSize -Property Name, FolderPath, @{
                    Label      = "ItemsInFolder"
                    Expression = { $_.VisibleItemsInFolder }
                } |
                Out-String
            Write-Host $availableOwnerCalendarTable
        }
        Add-SharingFinding -RuleId "SHR110" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            folderPath = $script:NormalizedOwnerCalendarFolderPath
            reason     = $selectionReason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR110" -Reason $selectionReason
        return $false
    }

    $script:OwnerSelectedCalendar = $ownerCalendarStat
    $script:OwnerCalendarSubfolderSelected = $script:OwnerCalendarFolderPathSpecified -and
    ($ownerCalendarStat.FolderType -ne "Calendar")
    $script:OwnerCalendarFolderIdentity = Get-CanonicalMailboxFolderIdentity `
        -Mailbox $Owner `
        -CalendarRootName $script:OwnerCalendarRootName `
        -FolderPath $ownerCalendarStat.FolderPath.ToString()
    $script:OwnerCalendarLeafName = $ownerCalendarStat.Name
    foreach ($ownerNamedCalendar in @($script:OwnerCalendarStats)) {
        if (($null -ne $ownerNamedCalendar) -and (Test-SharingOutboxFolderName -Name $ownerNamedCalendar.Name)) {
            Register-SharingOutboxCalendar -Role Owner -FolderName ([string]$ownerNamedCalendar.Name)
        }
    }
    if ($script:OwnerCalendarSubfolderSelected) {
        $script:OwnerCalendarLeafNameCandidate = $ownerCalendarStat.Name
    }

    Write-Host -ForegroundColor Cyan "Prerequisite: Get-MailboxCalendarFolder -Identity `"$($script:OwnerCalendarFolderIdentity)`""
    try {
        $script:OwnerCalendarFolder = Invoke-SharingCollector -Name "OwnerCalendarFolder" -Action {
            Get-MailboxCalendarFolder -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop
        }
    } catch {
        $reason = "Selected owner calendar ownership evidence is unavailable."
        Add-SharingFinding -RuleId "SHR123" -Status NotEvaluated -Area "Owner calendar prerequisite" -Evidence @{
            reason = $reason
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR123" -Reason $reason
        return $false
    }

    $actualOwnerCalendarOwner = [string]$script:OwnerCalendarFolder.CalendarSharingOwnerSmtpAddress
    if ((-not [string]::IsNullOrWhiteSpace($actualOwnerCalendarOwner)) -and
        (-not (Test-SmtpAddressEqual -First $actualOwnerCalendarOwner -Second $Owner))) {
        $inputsReversed = Test-SmtpAddressEqual -First $actualOwnerCalendarOwner -Second $Receiver
        if ($inputsReversed) {
            Write-Host -ForegroundColor Red "Selected Owner Calendar ownership mismatch. Expected Owner: [$Owner]. Actual calendar owner: [$actualOwnerCalendarOwner]. The Owner and Receiver appear reversed. Rerun the script with Owner and Receiver swapped."
        } else {
            Write-Host -ForegroundColor Red "Selected Owner Calendar ownership mismatch. Expected Owner: [$Owner]. Actual calendar owner: [$actualOwnerCalendarOwner]. The selected folder is a shared copy owned by another mailbox. Correct the Owner or owner calendar folder path."
        }
        Add-SharingFinding -RuleId "SHR123" -Status Detected -Area "Owner calendar identity" -Evidence @{
            expectedOwner  = $Owner
            actualOwner    = $actualOwnerCalendarOwner
            inputsReversed = $inputsReversed
        }
        $reason = if ($inputsReversed) {
            "Selected owner calendar belongs to the supplied Receiver; Owner and Receiver appear reversed."
        } else {
            "Selected owner calendar belongs to another mailbox."
        }
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR123" -Reason $reason
        return $false
    }

    return $true
}
