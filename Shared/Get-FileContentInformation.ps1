# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-ScriptBlockHandler.ps1
function Get-FileContentInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$FileLocation
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $allFiles = New-Object System.Collections.Generic.List[string]
    }
    process {
        foreach ($file in $FileLocation) {
            $allFiles.Add($file)
        }
    }
    end {
        $params = @{
            ComputerName           = $ComputerName
            ScriptBlockDescription = "Getting File Content Information"
            ArgumentList           = @(, $allFiles)
            ScriptBlock            = {
                param($FileLocations)
                $results = @{}
                foreach ($fileLocation in $FileLocations) {
                    $present = (Test-Path $fileLocation)

                    if ($present) {
                        $content = Get-Content $fileLocation -Raw -Encoding UTF8
                    } else {
                        $content = $null
                    }

                    $obj = [PSCustomObject]@{
                        Present  = $present
                        FileName = ([IO.Path]::GetFileName($fileLocation))
                        FilePath = $fileLocation
                        Content  = $content
                    }

                    $results.Add($fileLocation, $obj)
                }
                return $results
            }
        }
        return (Invoke-ScriptBlockHandler @params)
    }
}
