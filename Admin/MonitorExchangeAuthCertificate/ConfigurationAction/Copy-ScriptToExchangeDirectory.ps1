# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Copy-ScriptToExchangeDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$FullPathToScript = $MyInvocation.ScriptName,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $exchangeInstallPath = $env:ExchangeInstallPath
    $scriptName = $FullPathToScript.Split("\")[-1]

    if ($null -ne $exchangeInstallPath) {
        Write-Verbose ("ExchangeInstallPath is: $($exchangeInstallPath)")
        $localScriptsPath = [System.IO.Path]::Combine($exchangeInstallPath, "Scripts")

        try {
            if (-not(Test-Path -Path $localScriptsPath)) {
                Write-Verbose ("Folder: $($localScriptsPath) doesn't exist - it will be created now")

                if ($PSCmdlet.ShouldProcess("$exchangeInstallPath\Scripts", "New-Item")) {
                    New-Item -Path $exchangeInstallPath -ItemType Directory -Name "Scripts" -ErrorAction Stop | Out-Null
                }
            }

            if (($WhatIfPreference) -or
                (Test-Path -Path $localScriptsPath -ErrorAction Stop)) {
                Write-Verbose ("Path: $($localScriptsPath) was successfully created")
                if ($PSCmdlet.ShouldProcess("Copy: $FullPathToScript To: $localScriptsPath", "Copy-Item")) {
                    Copy-Item -Path $FullPathToScript -Destination $localScriptsPath -Force -ErrorAction Stop
                }

                if (($WhatIfPreference) -or
                    (Test-Path -Path $FullPathToScript)) {
                    Write-Verbose ("Script: $($scriptName) successfully copied over to: $($localScriptsPath)")
                    return [PSCustomObject]@{
                        WorkingDirectory = $localScriptsPath
                        ScriptName       = $scriptName
                    }
                }
            }
        } catch {
            Write-Verbose ("Something went wrong - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    return
}
