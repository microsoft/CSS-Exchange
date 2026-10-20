# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing-specific identity and permission utility functions.

. $PSScriptRoot\..\CalendarHelpers\CalendarDiagnosticHelpers.ps1

function Test-SmtpAddressEqual {
    param(
        [AllowNull()]
        [object]$First,

        [AllowNull()]
        [object]$Second
    )

    if (($null -eq $First) -or ($null -eq $Second)) {
        return $false
    }

    return [string]::Equals(
        $First.ToString().Trim(),
        $Second.ToString().Trim(),
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PermissionEntriesForIdentity {
    param(
        [AllowNull()]
        [object[]]$PermissionEntries,

        [Parameter(Mandatory)]
        [string]$Identity
    )

    return @($PermissionEntries | Where-Object -FilterScript {
            (Test-SmtpAddressEqual -First $_.User -Second $Identity) -or
            (Test-SmtpAddressEqual -First (Get-CalendarDiagnosticPermissionIdentity -PermissionUser $_.User) -Second $Identity) -or
            (Test-SmtpAddressEqual -First $_.User.PrimarySmtpAddress -Second $Identity) -or
            (Test-SmtpAddressEqual -First $_.User.RecipientPrincipal.PrimarySmtpAddress -Second $Identity)
        })
}

function Test-SharingPermissionFlagsDiffer {
    param(
        [AllowNull()]
        [object[]]$FirstFlags,

        [AllowNull()]
        [object[]]$SecondFlags
    )

    # The Editor access right can appear in only one side's flags even when the pair is configured correctly, so it is not a meaningful difference.
    # Flag enumerations stringify as a single comma-separated value such as "Editor, Delegate", so split each value into individual flags.
    $normalizeFlags = {
        param($Flags)
        @($Flags | ForEach-Object { if ($null -ne $_) { $_.ToString() -split ',' } } |
                ForEach-Object { $_.Trim() } |
                Where-Object -FilterScript { (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -ne "Editor") })
    }
    $normalizedFirstFlags = & $normalizeFlags $FirstFlags
    $normalizedSecondFlags = & $normalizeFlags $SecondFlags

    return (($normalizedFirstFlags -join ",") -ne ($normalizedSecondFlags -join ","))
}

function Get-PermissionRightsText {
    param(
        [AllowNull()]
        [object[]]$PermissionEntries,

        [switch]$IncludeSharingFlags
    )

    $accessRights = @($PermissionEntries | ForEach-Object {
            @($_.AccessRights) | ForEach-Object {
                if ($null -ne $_) {
                    $_.ToString()
                }
            }
        } | Sort-Object -Unique)
    $rightsText = if ($accessRights.Count -gt 0) {
        $accessRights -join ", "
    } else {
        "None"
    }
    if ($IncludeSharingFlags) {
        $sharingFlags = @($PermissionEntries | ForEach-Object {
                @($_.SharingPermissionFlags) | ForEach-Object {
                    if (-not [string]::IsNullOrWhiteSpace([string]$_)) {
                        $_.ToString()
                    }
                }
            } | Sort-Object -Unique)
        if ($sharingFlags.Count -gt 0) {
            $rightsText = "$rightsText; SharingPermissionFlags: $($sharingFlags -join ', ')"
        }
    }

    return $rightsText
}

function Test-UninitializedCalendarDate {
    param(
        [AllowNull()]
        [object]$Value
    )

    $dateValue = $Value -as [DateTime]
    return ($null -ne $dateValue) -and ($dateValue.Year -eq 1)
}
