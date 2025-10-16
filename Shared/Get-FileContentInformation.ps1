# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Gets the file information related to the passed list of files to the function.
    It will determine if the file exists and the raw content information for the file.
.NOTES
    You MUST execute this code on the server you want to collect information for. This can be done remotely via Invoke-Command/Invoke-ScriptBlockHandler.
#>
function Get-FileContentInformation {
    [CmdletBinding()]
    [OutputType([HashTable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$FileLocation
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $results = @{}
    }
    process {
        foreach ($file in $FileLocation) {
            $present = (Test-Path $file)

            if ($present) {
                $content = Get-Content $file -Raw -Encoding UTF8
            } else {
                $content = $null
            }

            $obj = [PSCustomObject]@{
                Present  = $present
                FileName = ([IO.Path]::GetFileName($file))
                FilePath = $file
                Content  = $content
            }
            $results.Add($file, $obj)
        }
    }
    end {
        return $results
    }
}
