# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "TestAMSI", HelpUri = "https://aka.ms/css-exchange")]
param(
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeServerFQDN,
    [switch]$IgnoreSSL,
    [Parameter(ParameterSetName = 'CheckAMSIProviders', Mandatory = $false)]
    [switch]$CheckAMSIProviders,
    [Parameter(ParameterSetName = 'EnableAMSI', Mandatory = $false)]
    [switch]$EnableAMSI,
    [Parameter(ParameterSetName = 'DisableAMSI', Mandatory = $false)]
    [switch]$DisableAMSI,
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $false)]
    [switch]$RestartIIS
)

Function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    } else {
        return $false
    }
}

function SetCertificateValidationBehavior {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "Ignore", Mandatory = $true)]
        [switch]
        $Ignore,

        [Parameter(ParameterSetName = "Default", Mandatory = $true)]
        [switch]
        $Default
    )

    if ($Ignore) {
        Add-Type @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationBehavior
        {
            public static void Ignore()
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate(Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                    {
                        return true;
                    };
            }
        }
"@
        [ServerCertificateValidationBehavior]::Ignore()
    } else {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

function Test-AMSI {
    $msgNewLine = "`n"
    $currentForegroundColor = $host.ui.RawUI.ForegroundColor
    if (-not (Confirm-Administrator)) {
        Write-Output $msgNewLine
        Write-Warning "This script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator and try again."
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }
    $datetime = Get-Date
    $installpath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($ExchangeServerFQDN) {
        try {
            if ($IgnoreSSL) {
                SetCertificateValidationBehavior -Ignore
            }

            $CookieContainer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $Cookie = New-Object System.Net.Cookie("X-BEResource", "a]@$($ExchangeServerFQDN):444/ecp/proxyLogon.ecp#~1941997017", "/", "$ExchangeServerFQDN")
            $CookieContainer.Cookies.Add($Cookie)
            Invoke-WebRequest https://$ExchangeServerFQDN/ecp/x.js -Method POST -Headers @{"Host" = "$ExchangeServerFQDN" } -WebSession $CookieContainer
        } catch [System.Net.WebException] {
            If ($_.Exception.Message -notlike "*: (400)*") {
                $Message = ($_.Exception.Message).ToString().Trim()
                Write-Output $msgNewLine
                Write-Error $Message
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "If you are using Microsoft Defender then AMSI may be disabled or you are using a AntiVirus Product that may not be AMSI capable (Please Check with your AntiVirus Provider for Exchange AMSI Support)"
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
                Write-Output $msgNewLine
            } else {
                Write-Output $msgNewLine
                $host.ui.RawUI.ForegroundColor = "Green"
                Write-Output "We sent an test request to the ECP Virtual Directory of the server requested"
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output "The remote server returned an error: (400) Bad Request"
                $host.ui.RawUI.ForegroundColor = "Green"
                Write-Output "---------------------------------------------------------------------------------------------------------------"
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "This may be indicative of a potential block from AMSI"
                $host.ui.RawUI.ForegroundColor = "Green"
                $msgCheckLogs = "Check your log files located in " + $installpath + "Logging\HttpRequestFiltering\"
                Write-Output $msgCheckLogs
                $msgDetectedTimeStamp = "for a Detected result around " + $datetime.ToUniversalTime()
                Write-Output $msgDetectedTimeStamp
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
                Write-Output $msgNewLine
            }
        } finally {
            if ($IgnoreSSL) {
                SetCertificateValidationBehavior -Default
            }
        }
        return
    }
    if ($CheckAMSIProviders) {
        $AMSI = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -Recurse
        $AMSI -match '[0-9A-Fa-f\-]{36}' | Out-Null
        $Matches.Values | ForEach-Object { Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID\{$_}" | Format-Table -AutoSize }
    }
    if ($EnableAMSI) {
        Remove-SettingOverride -Identity DisablingAMSIScan -Confirm:$false
        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
        Write-Warning "Remember to restart IIS for this to take affect. You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
        return
    }
    if ($DisableAMSI) {
        New-SettingOverride -Name DisablingAMSIScan -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script"
        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
        Write-Warning "Remember to restart IIS for this to take affect. You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
        return
    }
    if ($RestartIIS) {
        Restart-Service -Name W3SVC, WAS -Force
        return
    }
}

Test-AMSI
