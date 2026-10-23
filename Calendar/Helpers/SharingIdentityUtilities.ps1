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

function Get-SharingMailboxSmtpAddresses {
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [AllowNull()]
        [object]$Mailbox
    )

    $addresses = @($Identity, $Mailbox.PrimarySmtpAddress) +
    @($Mailbox.EmailAddresses | Where-Object { [string]$_ -match "^(?i)smtp:" } |
            ForEach-Object { ([string]$_).Substring(5) })
    return @($addresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
}

function Get-PermissionEntriesForIdentity {
    param(
        [AllowNull()]
        [object[]]$PermissionEntries,

        [Parameter(Mandatory)]
        [string]$Identity,

        [AllowNull()]
        [object]$Mailbox
    )

    $smtpAddresses = Get-SharingMailboxSmtpAddresses -Identity $Identity -Mailbox $Mailbox
    return @($PermissionEntries | Where-Object -FilterScript {
            $permissionUser = $_.User
            $permissionText = ([string]$permissionUser).Trim()
            $recipientTypes = @($permissionUser.ADRecipient.RecipientType, $permissionUser.ADRecipient.RecipientTypeDetails,
                $permissionUser.RecipientPrincipal.RecipientType, $permissionUser.RecipientPrincipal.RecipientTypeDetails,
                $permissionUser.RecipientType, $permissionUser.RecipientTypeDetails, $permissionUser.UserType)
            if (($permissionText -in @("Default", "Anonymous", "NT AUTHORITY\SELF")) -or
                @($recipientTypes | Where-Object { [string]$_ -match "Group" }).Count -gt 0) {
                return $false
            }

            $permissionAddresses = @($permissionUser.ADRecipient.PrimarySmtpAddress,
                $permissionUser.PrimarySmtpAddress, $permissionUser.RecipientPrincipal.PrimarySmtpAddress) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
                $permissionIdentities = if (@($permissionAddresses).Count -gt 0) { @($permissionAddresses) } else { @($permissionText) }
                foreach ($permissionIdentity in $permissionIdentities) {
                    if (@($smtpAddresses | Where-Object {
                                Test-SmtpAddressEqual -First $permissionIdentity -Second $_
                            }).Count -gt 0) {
                        return $true
                    }
                }
                # A readable display name is a fallback, not a reason to override a different SMTP identity.
                if ((@($permissionAddresses).Count -gt 0) -or ($permissionText -match "^[^@\s]+@[^@\s]+$") -or
                    [string]::IsNullOrWhiteSpace([string]$Mailbox.DisplayName)) {
                    return $false
                }
                return (Test-SmtpAddressEqual -First $permissionText -Second $Mailbox.DisplayName) -or
                (Test-SmtpAddressEqual -First $permissionUser.DisplayName -Second $Mailbox.DisplayName)
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
