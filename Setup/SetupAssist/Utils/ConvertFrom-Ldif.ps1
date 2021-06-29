# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function ConvertFrom-Ldif {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
        $LdifData
    )

    begin {
        $allLines = @()
    }

    process {
        foreach ($line in $LdifData) {
            $allLines += $line
        }
    }

    end {
        $unfoldedLdif = Get-UnfoldedLdif -LdifData $allLines
        Get-LdifObjects -UnfoldedLdifData $unfoldedLdif
    }
}

function Get-UnfoldedLdif {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter()]
        [string[]]
        $LdifData
    )

    process {
        $unfolded = @()

        for ($i = 0; $i -lt $LdifData.Length; $i++) {
            $line = $LdifData[$i]
            if ($line.StartsWith(" ")) {
                $unfolded[$unfolded.Length - 1] += $line.Substring(1)
            } else {
                $unfolded += $line
            }
        }

        $unfolded
    }
}

function Get-LdifObjects {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter()]
        [string[]]
        $UnfoldedLdifData
    )

    process {
        [PSCustomObject[]]$objects = @()

        $currentObject = @{}

        for ($i = 0; $i -lt $UnfoldedLdifData.Length; $i++) {
            $line = $UnfoldedLdifData[$i]
            if ($line.Length -lt 1) {
                if ($null -ne $currentObject["dn"]) {
                    $objects += $currentObject
                    $currentObject = @{}
                }
            } else {
                $propName = $line.Substring(0, $line.IndexOf(":"))
                $propValue = $line.Substring($line.IndexOf(":") + 2)
                if ($null -eq $currentObject[$propName]) {
                    $currentObject[$propName] = @()
                }

                $currentObject[$propName] += $propValue
            }
        }

        $objects
    }
}
