# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Common code to get the string value to run Invoke-Expression against.
# Need to return the string value as we can't run Invoke-Expression from inside this function as it won't expose it to the caller
function Get-PesterScriptContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
    [CmdletBinding()]
    [OutputType("System.String")]
    param(
        [string[]]$FilePath
    )
    . $PSScriptRoot\..\.build\BuildFunctions\Get-ExpandedScriptContent.ps1
    $pesterExtract = "# Extract for Pester Testing - Start"
    $scriptContentString = [string]::Empty

    foreach ($file in $FilePath) {

        $scriptContent = Get-ExpandedScriptContent -File $file
        $mainInternalFunctions = New-Object 'System.Collections.Generic.List[string]'

        while ($true) {
            $startIndex = $scriptContent.Trim().IndexOf($pesterExtract)
            $internalFunctions = New-Object 'System.Collections.Generic.List[string]'

            if ($startIndex -eq -1) { break }

            for ($i = $startIndex + 1; $i -lt $scriptContent.Count; $i++) {
                if ($scriptContent[$i].Trim().Contains($pesterExtract)) {
                    $startIndex = $i
                    $internalFunctions = New-Object 'System.Collections.Generic.List[string]'
                } elseif ($scriptContent[$i].Trim().Contains($pesterExtract.Replace("Start", "End"))) {
                    $endIndex = $i
                    break
                }

                $internalFunctions.Add($scriptContent[$i])
            }
            $scriptContent.RemoveRange($startIndex, $endIndex - $startIndex + 1)
            $mainInternalFunctions.AddRange($internalFunctions)
        }

        $scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }

        if ($mainInternalFunctions.Count -gt 0) {
            $mainInternalFunctions | ForEach-Object { $scriptContentString += "$($_)`n" }
        }
    }

    return $scriptContentString
}
