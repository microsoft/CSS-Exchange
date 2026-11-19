# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing evidence conversion and identity redaction.
# cSpell:ignore Sharee

function ConvertTo-SharingErrorInfo {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $ErrorRecord
    $message = $errorInfo.message
    if ($message.Length -gt 1024) {
        $message = $message.Substring(0, 1024)
    }
    if (-not $IncludeSensitiveData) {
        $message = "Error details omitted in sanitized mode."
    }

    return [PSCustomObject]@{
        message       = $message
        exceptionType = $errorInfo.exceptionType
    }
}

function Get-SanitizedSharingIdentity {
    param(
        [AllowNull()]
        [object]$Identity
    )

    $identityText = [string]$Identity
    if ($IncludeSensitiveData) {
        return $identityText
    }
    if (Test-SmtpAddressEqual -First $identityText -Second $Owner) {
        return "Owner"
    }
    if (Test-SmtpAddressEqual -First $identityText -Second $Receiver) {
        return "Receiver"
    }

    $identityKey = $identityText.Trim().ToLowerInvariant()
    if ($script:SanitizedIdentityMap.ContainsKey($identityKey)) {
        return $script:SanitizedIdentityMap[$identityKey]
    }
    $script:SanitizedIdentitySequence++
    $placeholder = "Identity-$($script:SanitizedIdentitySequence)"
    $script:SanitizedIdentityMap[$identityKey] = $placeholder
    return $placeholder
}

function ConvertTo-SharingEvidence {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern("^SHR\d{3}$")]
        [string]$RuleId,

        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return @{}
    }
    if ($Evidence -is [System.Collections.IDictionary] -or $Evidence -is [PSCustomObject]) {
        if ($IncludeSensitiveData) {
            return $Evidence
        }

        $sanitizedEvidence = [ordered]@{}
        $evidenceProperties = if ($Evidence -is [System.Collections.IDictionary]) {
            @($Evidence.Keys | ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_; Value = $Evidence[$_] }
                })
        } else {
            @($Evidence.PSObject.Properties | ForEach-Object {
                    [PSCustomObject]@{ Name = $_.Name; Value = $_.Value }
                })
        }
        foreach ($property in $evidenceProperties) {
            if ($property.Name -match "(?i)publishingUrl|url") {
                $sanitizedEvidence[$property.Name] = "UrlOmitted"
            } elseif ($property.Name -match "(?i)folderName|folderPath") {
                $sanitizedEvidence[$property.Name] = "Folder"
            } elseif ($property.Name -match "(?i)^(owner|receiver)(Count|Bytes)$") {
                $sanitizedEvidence[$property.Name] = $property.Value
            } elseif ($property.Name -match "(?i)^actualOwner$") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Name -match "(?i)owner") {
                $sanitizedEvidence[$property.Name] = "Owner"
            } elseif ($property.Name -match "(?i)receiver") {
                $sanitizedEvidence[$property.Name] = "Receiver"
            } elseif ($property.Name -match "(?i)identity|email|smtp|displayName") {
                $sanitizedEvidence[$property.Name] = Get-SanitizedSharingIdentity -Identity $property.Value
            } elseif ($property.Name -match "(?i)(SyncTime|SyncStartDate|EntryUtc)$") {
                $sanitizedEvidence[$property.Name] = $property.Value
            } elseif ($property.Value -is [string]) {
                $sanitizedEvidence[$property.Name] = if ($property.Name -in @("reason", "source", "mailboxRole", "fieldName")) {
                    $boundedValue = $property.Value -replace '[\r\n\t]+', ' '
                    if ($boundedValue.Length -gt 256) {
                        $boundedValue.Substring(0, 256)
                    } else {
                        $boundedValue
                    }
                } else {
                    "ValueOmitted"
                }
            } else {
                $sanitizedEvidence[$property.Name] = $property.Value
            }
        }
        return $sanitizedEvidence
    }

    $evidenceText = [string]$Evidence
    $values = @([regex]::Matches($evidenceText, '\[(?<Value>[^\]]*)\]') | ForEach-Object {
            $_.Groups["Value"].Value
        })
    $ownerValue = if ($IncludeSensitiveData) { [string]$Owner } else { "Owner" }
    $receiverValue = if ($IncludeSensitiveData) { [string]$Receiver } else { "Receiver" }

    switch ($RuleId) {
        "SHR100" { return @{ owner = $ownerValue; source = "Get-Mailbox" } }
        "SHR101" { return @{ owner = $ownerValue; piiAvailable = $false } }
        "SHR110" { return @{ owner = $ownerValue; source = "Get-MailboxFolderStatistics" } }
        "SHR111" { return @{ owner = $ownerValue; source = "Get-MailboxFolderPermission" } }
        "SHR120" { return @{ owner = $ownerValue; source = "Get-MailboxCalendarFolder" } }
        "SHR121" { return @{ owner = $ownerValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR122" { return @{ owner = $ownerValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR123" {
            return @{
                expectedOwner  = $ownerValue
                actualOwner    = $(if ($IncludeSensitiveData -and $values.Count -gt 1) {
                        Get-SanitizedSharingIdentity -Identity $values[1]
                    } else {
                        "Identity-1"
                    })
                inputsReversed = $(if ($values.Count -gt 2) { [bool]::Parse($values[2]) } else { $false })
            }
        }
        "SHR130" { return @{ owner = $ownerValue; source = "Get-MailboxPermission" } }
        "SHR200" { return @{ receiver = $receiverValue; source = "Get-Mailbox" } }
        "SHR201" { return @{ receiver = $receiverValue; piiAvailable = $false } }
        "SHR210" { return @{ receiver = $receiverValue; source = "Get-MailboxFolderStatistics" } }
        "SHR211" {
            $result = @{ receiver = $receiverValue; matchedFolderCount = [int]$values[0] }
            if ($IncludeSensitiveData -and $values.Count -gt 1) {
                $result.matchedFolderNames = @($values[1] -split ', ')
            }
            return $result
        }
        "SHR212" { return @{ receiver = $receiverValue; genericCalendarCount = "Multiple" } }
        "SHR213" {
            $result = @{ owner = $ownerValue; receiver = $receiverValue; matchedFolderCount = 0 }
            if ($IncludeSensitiveData -and $values.Count -gt 1) {
                $result.ownerDisplayName = $values[1]
            }
            return $result
        }
        "SHR220" {
            $result = @{ receiver = $receiverValue; source = "AcceptCalendarSharingInvite" }
            if ($evidenceText -match 'contained \[(?<ElementCount>\d+)\] comma-delimited') {
                $result.elementCount = [int]$Matches["ElementCount"]
            }
            return $result
        }
        "SHR230" { return @{ receiver = $receiverValue; source = "Get-CalendarEntries" } }
        "SHR231" { return @{ owner = $ownerValue; receiver = $receiverValue; newModelEntryFound = $false } }
        "SHR232" {
            $result = @{ owner = $ownerValue; receiver = $receiverValue; isOrphanedEntry = $true }
            if ($IncludeSensitiveData -and $values.Count -gt 0) {
                $result.calendarName = $values[0]
            }
            return $result
        }
        "SHR233" {
            return @{
                owner              = $ownerValue
                receiver           = $receiverValue
                oldModelEntryCount = $(if ($values.Count -gt 0) { [int]$values[0] } else { 1 })
            }
        }
        "SHR240" { return @{ owner = $ownerValue; receiver = $receiverValue; source = "Get-MailboxCalendarFolder" } }
        "SHR241" { return @{ receiver = $receiverValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR242" { return @{ receiver = $receiverValue; extendedFolderFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR243" {
            return @{
                expectedOwner = $ownerValue
                actualOwner   = $(if ($IncludeSensitiveData -and $values.Count -gt 1) {
                        Get-SanitizedSharingIdentity -Identity $values[1]
                    } else {
                        "Identity-1"
                    })
            }
        }
        "SHR300" { return @{ owner = $ownerValue; source = "CalendarSharingInvite" } }
        "SHR301" { return @{ owner = $ownerValue; receiver = $receiverValue; matchingInviteFound = $false } }
        "SHR310" { return @{ owner = $ownerValue; source = "Get-CalendarActiveSharingInformation" } }
        "SHR311" { return @{ owner = $ownerValue; receiver = $receiverValue; activeRelationshipFound = $false } }
        "SHR312" { return @{ receiver = $receiverValue; activeShareeFlags = @($values[0] -split ', ' | Where-Object { $_ }) } }
        "SHR320" { return @{ receiver = $receiverValue; activeRelationshipFound = $true; ownerPermissionFound = $false } }
        "SHR321" { return @{ receiver = $receiverValue; activeRelationshipFound = $false; ownerPermissionFound = $true } }
        "SHR322" {
            return @{
                ownerFlags    = @($values[0] -split ', ' | Where-Object { $_ })
                receiverFlags = @($values[1] -split ', ' | Where-Object { $_ })
            }
        }
        "SHR323" {
            return @{
                activeRelationshipFlags = @($values[0] -split ', ' | Where-Object { $_ })
                receiverFlags           = @($values[1] -split ', ' | Where-Object { $_ })
            }
        }
        "SHR400" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
                staleThresholdHours    = 24
            }
        }
        "SHR401" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR402" {
            return @{
                lastAttemptedSyncTime  = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                lastSuccessfulSyncTime = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR410" { return @{ sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null }) } }
        "SHR411" {
            return @{
                sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null })
                folderCreationTime          = $(if ($values.Count -gt 1) { $values[1] } else { $null })
            }
        }
        "SHR412" { return @{ sharedCalendarSyncStartDate = $(if ($values.Count -gt 0) { $values[0] } else { $null }) } }
        "SHR413" { return @{ sharedCalendarSyncStartDate = $null } }
        "SHR420" { return @{ receiver = $receiverValue; source = "InternetCalendar" } }
        default { return @{ observed = $true } }
    }
}
