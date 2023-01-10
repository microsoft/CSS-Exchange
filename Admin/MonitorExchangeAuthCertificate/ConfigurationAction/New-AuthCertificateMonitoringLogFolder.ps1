# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-AuthCertificateMonitoringLogFolder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only non-destructive operations are performed in this function.')]
    [CmdletBinding()]
    [OutputType([System.String])]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInstallPath = $env:ExchangeInstallPath
    if ($null -eq $exchangeInstallPath) {
        Write-Verbose ("ExchangeInstallPath environment variable doesn't exist - fallback to use temp folder to store logs")
        $exchangeInstallPath = $env:TEMP
    }

    if ($null -ne $exchangeInstallPath) {
        $logFilePath = [System.IO.Path]::Combine($exchangeInstallPath, "Logging")
        $finalLogPath = [System.IO.Path]::Combine($logFilePath, "AuthCertificateMonitoring")

        if ((Test-Path -Path $finalLogPath) -eq $false) {
            New-Item -Path $logFilePath -ItemType Directory -Name "AuthCertificateMonitoring" -ErrorAction SilentlyContinue | Out-Null
        }
        return $finalLogPath
    }

    return
}
