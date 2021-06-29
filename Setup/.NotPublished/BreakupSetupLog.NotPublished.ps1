# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [System.IO.FileInfo]$SetupLog
)

$validSetupLog = Select-String "Starting Microsoft Exchange Server \d\d\d\d Setup" $SetupLog

if ($null -eq $validSetupLog) {
    throw "Failed to provide valid setup log"
}

$index = 0
$allContent = [IO.File]::ReadAllLines($SetupLog.FullName)

$outFile = $SetupLog.FullName.Replace($SetupLog.Extension, "_Run{0}$($SetupLog.Extension)")

while ($index -lt $validSetupLog.Count) {
    $setupRun = $validSetupLog[$index]
    $instanceIndex = $setupRun.LineNumber - 2
    $newContent = New-Object 'System.Collections.Generic.List[string]'

    while ($instanceIndex -lt ($validSetupLog[$index + 1].LineNumber - 1 )) {
        $newContent.Add($allContent[$instanceIndex])
        $instanceIndex++
    }

    $newContent | Out-File -FilePath ($outFile -f "$index")
    $index++
}
