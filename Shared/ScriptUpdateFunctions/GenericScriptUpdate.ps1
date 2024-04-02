# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This set of code is designed to handle updating your script as this code is basically the same everywhere, making this a common file to avoid duplication.
    Just need to dot load the file to your script and have the correct parameters, then this code does the work for you.
    These are the parameters that you should have within your script.
    This needs to be done within the main part of the script, not inside a function to work correctly.

    [Parameter(Mandatory = $false, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [switch]$SkipVersionCheck
#>

. $PSScriptRoot\Test-ScriptVersion.ps1

$BuildVersion = ""
Write-Host ("$($script:MyInvocation.MyCommand.Name) script version $($BuildVersion)") -ForegroundColor Green

$scriptVersionParams = @{
    AutoUpdate = $true
    Confirm    = $false
}

# This needs to be set prior to injecting this file to other scripts.
if (-not ([string]::IsNullOrEmpty($versionsUrl))) {
    $scriptVersionParams.Add("VersionsUrl", $versionsUrl)
}

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion @scriptVersionParams) {
        ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    exit
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion @scriptVersionParams)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    exit
}
