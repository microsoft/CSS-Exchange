# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ScriptDependencyHashtable {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param (
        [Parameter()]
        [string[]]
        $FileNames
    )

    $deps = @{}

    $stack = New-Object 'System.Collections.Generic.Stack[string]'

    foreach ($file in $FileNames) {
        Write-Host "Getting dependencies for $([IO.Path]::GetFileName($file))"
        $stack.Push($file)
        while ($stack.Count -gt 0) {
            $currentFile = $stack.Pop()
            $currentFolder = [System.IO.Path]::GetDirectoryName($currentFile)
            $deps[$currentFile] = @()

            if ($currentFile.EndsWith(".ps1")) {
                Select-String "\. (?:\.|\`$PSScriptRoot)\\(.*).ps1" $currentFile | ForEach-Object {
                    $dotLoadedScriptPath = $_.Matches[0].Groups[1].Value + ".ps1"
                    $dotSourcedFile = (Get-Item (Join-Path $currentFolder $dotLoadedScriptPath)).FullName
                    $deps[$currentFile] += $dotSourcedFile
                    if ($null -eq $deps[$dotSourcedFile]) {
                        $stack.Push($dotSourcedFile)
                    }
                }

                Select-String "\`$(.+) = Get-Content `"?(\`$PSScriptRoot|\.)\\([\w|\d|\.|\\]+)`"? -AsByteStream -Raw" $currentFile | ForEach-Object {
                    $embeddedFilePath = $_.Matches[0].Groups[3].Value
                    $absolutePath = (Get-Item (Join-Path $currentFolder $embeddedFilePath)).FullName
                    $deps[$currentFile] += $absolutePath
                    if ($null -eq $deps[$absolutePath]) {
                        $stack.Push($absolutePath)
                    }
                }
            }
        }
    }

    return $deps
}
