# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-RemoteRegistryValue.ps1

function Get-NETFrameworkVersion {
    [CmdletBinding(DefaultParameterSetName = "CollectFromServer")]
    param(
        [Parameter(ParameterSetName = "CollectFromServer", Position = 1)]
        [string]$MachineName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = "NetKey")]
        [int]$NetVersionKey = -1,

        [Parameter(ParameterSetName = "NetName")]
        [ValidateScript({ ValidateNetNameParameter $_ })]
        [string]$NetVersionShortName,

        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $friendlyName = [string]::Empty
        $minValue = -1
        $netVersionDictionary = GetNetVersionDictionary

        if ($PSCmdlet.ParameterSetName -eq "NetName") {
            $NetVersionKey = $netVersionDictionary[$NetVersionShortName]
        }
    }
    process {

        if ($NetVersionKey -eq -1) {
            $params = @{
                MachineName         = $MachineName
                SubKey              = "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
                GetValue            = "Release"
                CatchActionFunction = $CatchActionFunction
            }
            [int]$NetVersionKey = Get-RemoteRegistryValue @params
        }

        #Using Minimum Version as per https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed?redirectedfrom=MSDN#minimum-version
        if ($NetVersionKey -lt $netVersionDictionary["Net4d5"]) {
            $friendlyName = "Unknown"
            $minValue = -1
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d5d1"]) {
            $friendlyName = "4.5"
            $minValue = $netVersionDictionary["Net4d5"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d5d2"]) {
            $friendlyName = "4.5.1"
            $minValue = $netVersionDictionary["Net4d5d1"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d6"]) {
            $friendlyName = "4.5.2"
            $minValue = $netVersionDictionary["Net4d5d2"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d6d1"]) {
            $friendlyName = "4.6"
            $minValue = $netVersionDictionary["Net4d6"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d6d2"]) {
            $friendlyName = "4.6.1"
            $minValue = $netVersionDictionary["Net4d6d1"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d7"]) {
            $friendlyName = "4.6.2"
            $minValue = $netVersionDictionary["Net4d6d2"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d7d1"]) {
            $friendlyName = "4.7"
            $minValue = $netVersionDictionary["Net4d7"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d7d2"]) {
            $friendlyName = "4.7.1"
            $minValue = $netVersionDictionary["Net4d7d1"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d8"]) {
            $friendlyName = "4.7.2"
            $minValue = $netVersionDictionary["Net4d7d2"]
        } elseif ($NetVersionKey -lt $netVersionDictionary["Net4d8d1"]) {
            $friendlyName = "4.8"
            $minValue = $netVersionDictionary["Net4d8"]
        } elseif ($NetVersionKey -ge $netVersionDictionary["Net4d8d1"]) {
            $friendlyName = "4.8.1"
            $minValue = $netVersionDictionary["Net4d8d1"]
        }
    }
    end {
        Write-Verbose "FriendlyName: $friendlyName | RegistryValue: $netVersionKey | MinimumValue: $minValue"
        return [PSCustomObject]@{
            FriendlyName  = $friendlyName
            RegistryValue = $NetVersionKey
            MinimumValue  = $minValue
        }
    }
}

function GetNetVersionDictionary {
    return @{
        "Net4d5"       = 378389
        "Net4d5d1"     = 378675
        "Net4d5d2"     = 379893
        "Net4d5d2wFix" = 380035
        "Net4d6"       = 393295
        "Net4d6d1"     = 394254
        "Net4d6d1wFix" = 394294
        "Net4d6d2"     = 394802
        "Net4d7"       = 460798
        "Net4d7d1"     = 461308
        "Net4d7d2"     = 461808
        "Net4d8"       = 528040
        "Net4d8d1"     = 533320
    }
}

function ValidateNetNameParameter {
    param($name)
    $netVersionNames = @((GetNetVersionDictionary).Keys)
    $netVersionNames.Contains($name)
}
