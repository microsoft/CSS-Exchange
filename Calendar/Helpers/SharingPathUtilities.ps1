# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing-specific calendar path and folder utilities.

function ConvertTo-NormalizedCalendarFolderPath {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath
    )

    $normalizedFolderPath = $FolderPath.Trim()
    if ([string]::IsNullOrWhiteSpace($normalizedFolderPath)) {
        throw "OwnerCalendarFolderPath cannot be empty or whitespace."
    }
    if ($normalizedFolderPath -match "^[^\\/]+:\s*[\\/]") {
        throw "OwnerCalendarFolderPath must contain only the owner-relative path. Do not provide a mailbox identity prefix such as owner@contoso.com:\."
    }

    $normalizedFolderPath = $normalizedFolderPath.Replace("/", "\").TrimStart("\")
    $normalizedFolderPath = $normalizedFolderPath -replace "\\+", "\"
    if ([string]::IsNullOrWhiteSpace($normalizedFolderPath)) {
        throw "OwnerCalendarFolderPath must identify a folder in the owner mailbox."
    }

    return "\$normalizedFolderPath"
}

function Get-CanonicalMailboxFolderIdentity {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CalendarRootName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath
    )

    $normalizedFolderPath = ConvertTo-NormalizedCalendarFolderPath -FolderPath $FolderPath
    $normalizedCalendarRootPath = ConvertTo-NormalizedCalendarFolderPath -FolderPath $CalendarRootName
    if (($normalizedFolderPath -ne $normalizedCalendarRootPath) -and
        (-not $normalizedFolderPath.StartsWith(
            "$normalizedCalendarRootPath\",
            [System.StringComparison]::OrdinalIgnoreCase))) {
        $normalizedFolderPath = "$normalizedCalendarRootPath$normalizedFolderPath"
    }

    return "${Mailbox}:$normalizedFolderPath"
}

function ConvertTo-NormalizedFolderFlags {
    param(
        [AllowNull()]
        [object[]]$Flags
    )

    return @(
        foreach ($flag in $Flags) {
            if ($null -eq $flag) {
                continue
            }

            foreach ($token in @($flag.ToString() -split ",")) {
                $normalizedFlag = $token.Trim()
                if (-not [string]::IsNullOrWhiteSpace($normalizedFlag)) {
                    $normalizedFlag
                }
            }
        }
    )
}

function Get-DuplicateStyleCalendarFolders {
    param(
        [AllowNull()]
        [object[]]$FolderStatistics
    )

    return @($FolderStatistics | Where-Object -FilterScript {
            $folderName = if (-not [string]::IsNullOrWhiteSpace([string]$_.Name)) {
                [string]$_.Name
            } else {
                [string]$_.FolderPath
            }
            $folderName -match "\(\d{1,2}\)\s*$"
        })
}
