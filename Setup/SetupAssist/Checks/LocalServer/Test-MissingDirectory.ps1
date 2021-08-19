# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-MissingDirectory {
    [CmdletBinding()]
    param()
    begin {
        $result = "Passed"
        $context = [string]::Empty
        $directories = New-Object 'System.Collections.Generic.List[string]'
        $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
        $owaVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).OwaVersion
        $checkLocations = @("UnifiedMessaging\Grammars", "UnifiedMessaging\Prompts")
    }
    process {
        if ($null -ne $installPath -and
            (Test-Path $installPath) -and
            $owaVersion -notlike "15.2.*") {
            foreach ($path in $checkLocations) {

                if (-not (Test-Path ([System.IO.Path]::Combine($installPath, $path)))) {
                    $result = "Failed"
                    $directories.Add([System.IO.Path]::Combine($installPath, $path))
                }
            }

            if ($directories.Count -gt 0) {
                $context = "Missing $($directories.Count)"
            }
        }
    }
    end {
        $params = @{
            TestName          = "Missing Directories"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $directories
        }

        return (New-TestResult @params)
    }
}
