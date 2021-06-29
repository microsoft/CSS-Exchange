# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ItemCount {
    <#
    .SYNOPSIS
        Populates the ItemCount property on our PSCustomObjects.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server
    )

    begin {
        $WarningPreference = "SilentlyContinue"
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }
    }

    process {
        $itemCounts = Get-PublicFolderStatistics -ResultSize Unlimited | ForEach-Object {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount
            }

            Select-Object -InputObject $_ -Property EntryId, ItemCount
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            ItemCounts = $itemCounts
        }
    }
}
