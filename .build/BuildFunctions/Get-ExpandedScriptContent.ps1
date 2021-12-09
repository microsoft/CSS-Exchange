# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-DotSourcedScriptName.ps1
. $PSScriptRoot\Get-EmbeddedFileInfo.ps1

<#
.SYNOPSIS
    Gets the content of the designated file, embedding the content of
    any dot-sourced scripts or embedded data files.
#>
function Get-ExpandedScriptContent {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[string]])]
    param (
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [System.Collections.Generic.HashSet[string]]
        $ScriptsAlreadyEmbedded = (New-Object 'System.Collections.Generic.HashSet[string]')
    )

    begin {
        $currentFolder = (Get-Item $File).DirectoryName
        Write-Verbose "Get-ExpandedScriptContent called for file $File"
    }

    process {
        $scriptContent = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent.AddRange([IO.File]::ReadAllLines($File))
        for ($i = 0; $i -lt $scriptContent.Count; $i++) {
            $line = $scriptContent[$i]
            $dotSourcedFile = $line | Get-DotSourcedScriptName
            if ($null -ne $dotSourcedFile) {
                $scriptContent.RemoveAt($i)
                $dotSourcedFile = (Get-Item (Join-Path $currentFolder $dotSourcedFile))
                # Scripts must only be embedded once
                if ($ScriptsAlreadyEmbedded.Add($dotSourcedFile)) {
                    $dotSourcedFileContent = Get-ExpandedScriptContent $dotSourcedFile $ScriptsAlreadyEmbedded
                    $scriptContent.InsertRange($i, $dotSourcedFileContent)
                }

                $i-- # Make sure we re-evaluate the line at this index after deleting what was here before
            } else {
                $embeddedFile = $line | Get-EmbeddedFileInfo
                if ($null -ne $embeddedFile) {
                    $absolutePath = (Get-Item (Join-Path $currentFolder $embeddedFile.FilePath)).FullName
                    $fileAsBase64 = [Convert]::ToBase64String(([IO.File]::ReadAllBytes($absolutePath)), "InsertLineBreaks")
                    $scriptContent.RemoveAt($i)
                    [string[]]$linesToInsert = @()
                    $linesToInsert += "`$$($embeddedFile.VariableName)Base64 = @'"
                    $linesToInsert += $fileAsBase64
                    $linesToInsert += "'@"
                    $linesToInsert += ""
                    $linesToInsert += "`$$($embeddedFile.VariableName) = [Convert]::FromBase64String(`$$($embeddedFile.VariableName)Base64)"
                    $scriptContent.InsertRange($i, $linesToInsert)
                }
            }
        }

        Write-Output -NoEnumerate -InputObject $scriptContent
    }
}
