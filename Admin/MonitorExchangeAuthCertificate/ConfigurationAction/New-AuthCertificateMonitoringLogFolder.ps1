# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-AuthCertificateMonitoringLogFolder {
    [CmdletBinding(SupportsShouldProcess)]
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
            if ($PSCmdlet.ShouldProcess("$logFilePath\AuthCertificateMonitoring", "New-Item")) {
                New-Item -Path $logFilePath -ItemType Directory -Name "AuthCertificateMonitoring" -ErrorAction SilentlyContinue | Out-Null
            }
        }
        return $finalLogPath
    }

    return
}
