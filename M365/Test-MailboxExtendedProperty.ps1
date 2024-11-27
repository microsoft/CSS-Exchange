# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules @{ ModuleName="ExchangeOnlineManagement"; ModuleVersion="3.4.0" }

<#
.SYNOPSIS
    Checks what mailbox extended properties (aka named properties) exist in the mailbox and if they are near to any limits.

.DESCRIPTION
    This script retrieves the mailbox extended properties for a specified user identity.

.PARAMETER Identity
    The identity of the user whose mailbox extended properties are to be retrieved.

.PARAMETER Threshold
    The quota threshold to check for having exceeded. Default is 0.9, which is 90% of the allowed quota.

.PARAMETER SelectFirst
    The number of sorted descending results to select, when checking any namespace or same name prefix quota. Default is 10.

.EXAMPLE
    .\Test-MailboxExtendedProperty.ps1 -Identity fred@contoso.com
    .\Test-MailboxExtendedProperty.ps1 -Identity fred@contoso.com -Threshold 0.95
    .\Test-MailboxExtendedProperty.ps1 -Identity fred@contoso.com -Threshold 0.7 -SelectFirst 20

#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    $Identity,
    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateRange(0.0, 1.0)]
    [double]$Threshold = 0.9,
    [Parameter(Mandatory = $false, Position = 2)]
    $SelectFirst = 10
)

process {
    Write-Host -ForegroundColor Blue "Checking the mailbox $Identity for having exceeded the threshold of $($Threshold * 100)% of any named properties quota."

    # Flag to indicate if the mailbox has exceeded the threshold of a named properties quota.
    $exceededThresholdQuota = $false
    # The Guid of the PublicStrings namespace.
    $publicStringsNamespace = "00020329-0000-0000-c000-000000000046"
    # The Guid of the InternetHeaders namespace.
    $internetHeadersNamespace = "00020386-0000-0000-C000-000000000046"
    # The length of the prefix to check for named properties with the same name.
    $prefixLength = 10

    # Retrieve the named properties.
    $namedProps = Get-MailboxExtendedProperty -Identity $Identity
    # Retrieve the named properties quota.
    $namedPropsQuota = Get-MailboxStatistics -Identity $Identity | Select-Object -ExpandProperty NamedPropertiesCountQuota

    # The PublicStrings namespace is allowed to be 20% of the named properties quota.
    $publicStringsQuota = [int](0.2 * $namedPropsQuota)
    # The InternetHeaders namespace is allowed to be 60% of the named properties quota.
    $internetHeadersQuota = [int](0.6 * $namedPropsQuota)
    # Any namespace is allowed to be 20% of the named properties quota.
    $anyNamespaceQuota = [int](0.2 * $namedPropsQuota)
    # The same 10 character name prefix is allowed to be 10% of the named properties quota.
    $sameNamePrefixQuota = [int](0.1 * $namedPropsQuota)

    Write-Host -ForegroundColor Gray "The total named properties quota is $namedPropsQuota."
    Write-Host -ForegroundColor Gray "The PublicStrings namespace named properties quota is $publicStringsQuota."
    Write-Host -ForegroundColor Gray "The InternetHeaders namespace named properties quota is $internetHeadersQuota."
    Write-Host -ForegroundColor Gray "The any namespace named properties quota is $anyNamespaceQuota."
    Write-Host -ForegroundColor Gray "The same name prefix named properties quota is $sameNamePrefixQuota."

    Write-Host -ForegroundColor Blue "Checking if the mailbox has exceeded the threshold of total named properties quota."
    if ($namedProps.Count -ge [int]($Threshold * $namedPropsQuota)) {
        Write-Host -ForegroundColor Yellow "The mailbox has $($namedProps.Count) named properties. The quota is $namedPropsQuota."
        $exceededThresholdQuota = $true
    } else {
        Write-Host -ForegroundColor Green "The mailbox is under quota with $($namedProps.Count) named properties."
    }

    $namedPropsPublicStrings = $namedProps | Where-Object { $_.PropertyNamespace -eq $publicStringsNamespace }
    $namedPropsInternetHeaders = $namedProps | Where-Object { $_.PropertyNamespace -eq $internetHeadersNamespace }

    Write-Host -ForegroundColor Blue "Checking if the mailbox has exceeded the threshold of PublicStrings namespace named properties quota."
    if ($namedPropsPublicStrings.Count -ge [int]($Threshold * $publicStringsQuota)) {
        Write-Host -ForegroundColor Yellow "The PublicStrings namespace has $($namedPropsPublicStrings.Count) named properties. The quota is $publicStringsQuota."
        $exceededThresholdQuota = $true
    } else {
        Write-Host -ForegroundColor Green "The PublicStrings namespace is under quota with $($namedPropsPublicStrings.Count) named properties."
    }

    Write-Host -ForegroundColor Blue "Checking if the mailbox has exceeded the threshold of InternetHeaders namespace named properties quota."
    if ($namedPropsInternetHeaders.Count -ge [int]($Threshold * $internetHeadersQuota)) {
        Write-Host -ForegroundColor Yellow "The InternetHeaders namespace has $($namedPropsInternetHeaders.Count) named properties. The quota is $internetHeadersQuota."
        $exceededThresholdQuota = $true
    } else {
        Write-Host -ForegroundColor Green "The InternetHeaders namespace is under quota with $($namedPropsInternetHeaders.Count) named properties."
    }

    Write-Host -ForegroundColor Blue "Checking if the mailbox has exceeded the threshold of any other namespace named properties quota."
    $namespaces = $namedProps | Where-Object { $_.PropertyNamespace -ne $publicStringsNamespace -or $_.PropertyNamespace -ne $internetHeadersNamespace } | Group-Object PropertyNamespace -NoElement | Sort-Object Count -Descending | Select-Object -First $SelectFirst
    foreach ($namespace in $namespaces) {
        if ($namespace.Count -ge [int]($Threshold * $anyNamespaceQuota)) {
            Write-Host -ForegroundColor Yellow "The $($namespace.Name) namespace has $($namespace.Count) named properties. The quota is $anyNamespaceQuota."
            $exceededThresholdQuota = $true
        } else {
            Write-Host -ForegroundColor Green "The $($namespace.Name) namespace is under quota with $($namespace.Count) named properties."
        }
    }

    Write-Host -ForegroundColor Blue "Checking if the mailbox has exceeded the threshold of named properties with the same name prefix quota."
    $propPrefix=@{}
    $namedProps | Where-Object { $_.PropertyType -eq "StringProperty" -and $_.PropertyName -ne $null } | ForEach-Object {
        $propPrefixKey = $_.PropertyName
        if ($propPrefixKey.Length -gt $prefixLength) {
            $propPrefixKey=$propPrefixKey.Substring(0, $prefixLength)
        }
        $propPrefix[$propPrefixKey]++
    }
    $topPropPrefix = $propPrefix.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First $SelectFirst

    foreach ($prefix in $topPropPrefix) {
        if ($prefix.Value -ge [int]($Threshold * $sameNamePrefixQuota)) {
            Write-Host -ForegroundColor Yellow "The $($prefix.Name) prefix has $($prefix.Value) named properties. The quota is $sameNamePrefixQuota."
            $exceededThresholdQuota = $true
        } else {
            Write-Host -ForegroundColor Green "The $($prefix.Name) prefix is under quota with $($prefix.Value) named properties."
        }
    }

    Write-Host -ForegroundColor Blue "Summary, checking $SelectFirst result(s) and threshold of $($Threshold * 100)%."
    if ($exceededThresholdQuota) {
        Write-Host -ForegroundColor Red "The mailbox has exceeded the threshold of a named properties quota. See above for which quota(s) have been exceeded."
    } else {
        Write-Host -ForegroundColor Green "The mailbox is under the threshold of each named properties quota."
    }
}
