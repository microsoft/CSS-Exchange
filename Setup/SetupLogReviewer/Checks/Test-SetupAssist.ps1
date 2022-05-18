# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SetupAssist {
    $name = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
    return $name -eq "SetupAssist.ps1"
}
