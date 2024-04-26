# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExportedHealthCheckerFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $importedItems = New-Object System.Collections.Generic.List[object]
        $customFileObject = New-Object System.Collections.Generic.List[object]
    }
    process {
        $allItems = @(Get-ChildItem $Directory |
                Where-Object { $_.Name -like "HealthChecker-*-*.xml" -and $_.Name -notlike "HealthChecker-ExchangeDCCoreRatio-*.xml" })

        if ($null -eq $allItems) {
            Write-Verbose "No items were found like HealthChecker-*-*.xml"
            return
        }

        $allItems |
            ForEach-Object {
                [string]$name = $_.Name
                $startIndex = $name.IndexOf("-")
                $serverName = $name.Substring(($startIndex + 1), ($name.LastIndexOf("-") - $startIndex - 1))
                $customFileObject.Add([PSCustomObject]@{
                        ServerName = $serverName
                        FileName   = $name
                        FileObject = $_
                    })
            }

        # Group the items by server name and then get the latest one and import that file.
        $groupResults = $customFileObject | Group-Object ServerName

        $groupResults |
            ForEach-Object {
                $sortedGroup = $_.Group | Sort-Object FileName -Descending
                $index = 0
                $continueLoop = $true

                do {
                    $fileName = $sortedGroup[$index].FileObject.VersionInfo.FileName
                    $data = Import-Clixml -Path $fileName

                    if ($null -ne $data -and
                        $null -ne $data.HealthCheckerExchangeServer) {
                        Write-Verbose "For Server $($_.Group[0].ServerName) using file: $fileName"
                        $importedItems.Add($data)
                        $continueLoop = $false
                    } else {
                        $index++
                        if ($index -ge $_.Count) {
                            $continueLoop = $false
                            Write-Red "Failed to find proper Health Checker data to import for server $($_.Group[0].ServerName)"
                        }
                    }
                } while ($continueLoop)
            }
    }
    end {
        if ($importedItems.Count -eq 0) {
            return $null
        }
        return $importedItems
    }
}
