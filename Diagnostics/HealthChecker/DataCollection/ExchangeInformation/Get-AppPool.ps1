# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-AppPool {
    [CmdletBinding()]
    param ()

    begin {
        function Get-IndentLevel ($line) {
            if ($line.StartsWith(" ")) {
                ($line | Select-String "^ +").Matches[0].Length
            } else {
                0
            }
        }

        function Convert-FromAppPoolText {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string[]]
                $Text,

                [Parameter(Mandatory = $false)]
                [int]
                $Line = 0,

                [Parameter(Mandatory = $false)]
                [int]
                $MinimumIndentLevel = 2
            )

            if ($Line -ge $Text.Count) {
                return $null
            }

            $startingIndentLevel = Get-IndentLevel $Text[$Line]
            if ($startingIndentLevel -lt $MinimumIndentLevel) {
                return $null
            }

            $hash = @{}

            while ($Line -lt $Text.Count) {
                $indentLevel = Get-IndentLevel $Text[$Line]
                if ($indentLevel -gt $startingIndentLevel) {
                    # Skip until we get to the next thing at this level
                } elseif ($indentLevel -eq $startingIndentLevel) {
                    # We have a property at this level. Add it to the object.
                    if ($Text[$Line] -match "\[(\S+)\]") {
                        $name = $Matches[1]
                        $value = Convert-FromAppPoolText -Text $Text -Line ($Line + 1) -MinimumIndentLevel $startingIndentLevel
                        $hash[$name] = $value
                    } elseif ($Text[$Line] -match "\s+(\S+):`"(.*)`"") {
                        $name = $Matches[1]
                        $value = $Matches[2].Trim("`"")
                        $hash[$name] = $value
                    }
                } else {
                    # IndentLevel is less than what we started with, so return
                    [PSCustomObject]$hash
                    return
                }

                ++$Line
            }

            [PSCustomObject]$hash
        }

        $appPoolCmd = "$env:windir\System32\inetsrv\appcmd.exe"
    }

    process {
        $appPoolNames = & $appPoolCmd list apppool |
            Select-String "APPPOOL `"(\S+)`" " |
            ForEach-Object { $_.Matches.Groups[1].Value }

        foreach ($appPoolName in $appPoolNames) {
            $appPoolText = & $appPoolCmd list apppool $appPoolName /text:*
            Convert-FromAppPoolText -Text $appPoolText -Line 1
        }
    }
}
