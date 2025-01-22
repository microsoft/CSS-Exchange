# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ErrorMonitorFunctions.ps1

function Test-IanaTimeZoneMapping {
    [CmdletBinding(DefaultParameterSetName = "FilePath")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "FilePath")]
        [string]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = "MappingFile")]
        [System.Xml.XmlNode]$IanaMappingFile
    )

    begin {
        $xmlMap = New-Object System.Collections.Generic.HashSet[string]
        $xmlMissingAttributesList = New-Object System.Collections.Generic.HashSet[object]
        $xmlDuplicateEntriesList = New-Object System.Collections.Generic.List[object]
    } process {

        if ($PSCmdlet.ParameterSetName -eq "FilePath") {
            if ((Test-Path -Path $FilePath) -eq $false) {
                Write-Verbose "Path: $FilePath doesn't exist"

                return
            }

            try {
                [xml]$IanaMappingFile = Get-Content -Path $FilePath -ErrorAction Stop
            } catch {
                Write-Verbose "Exception while trying to import file: $FilePath - Exception: $_"
                Invoke-CatchActions
            }
        }

        try {
            $nodeList = $IanaMappingFile.SelectNodes("//Map")

            if ($null -eq $nodeList) {
                Write-Verbose "Failed to process XML file"

                return
            }

            foreach ($node in $nodeList) {

                [string]$iana = $node.Attributes["IANA"].Value
                [string]$win = $node.Attributes["Win"].Value
                $xmlMapKey = "$iana|$win"

                if ([System.String]::IsNullOrEmpty($iana) -or
                    [System.String]::IsNullOrEmpty($win)) {
                    Write-Verbose "Map node missing required attribute: $xmlMapKey"
                    #$xmlMissingAttributesList.Add("@IANA='$iana' and @Win='$win'")
                    $xmlMissingAttributesList.Add([PSCustomObject]@{
                            IANA = if ([System.String]::IsNullOrEmpty($iana)) { "N/A" } else { $iana }
                            Win  = if ([System.String]::IsNullOrEmpty($win)) { "N/A" } else { $win }
                        })

                    continue
                }

                if ($xmlMap -contains $xmlMapKey) {
                    Write-Verbose "Duplicate entry found: $xmlMapKey"
                    #$xmlDuplicateEntriesList.Add("@IANA='$iana' and @Win='$win'")
                    $xmlDuplicateEntriesList.Add([PSCustomObject]@{
                            IANA = $iana
                            Win  = $win
                        })

                    continue
                }

                [void]$xmlMap.Add($xmlMapKey)
            }
        } catch {
            Write-Verbose "Exception while processing content of the IanaTimeZoneMapping file - Exception: $_"
            Invoke-CatchActions
        }
    } end {
        return [PSCustomObject]@{
            IanaMappingXml        = $IanaMappingFile
            NodeMissingAttributes = $xmlMissingAttributesList
            DuplicateEntries      = $xmlDuplicateEntriesList
        }
    }
}
