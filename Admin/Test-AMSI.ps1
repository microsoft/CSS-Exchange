# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "TestAMSI", HelpUri = "https://aka.ms/css-exchange")]
param(
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeServerFQDN,
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $false)]
    [switch]$IgnoreSSL,
    [Parameter(ParameterSetName = 'CheckAMSIProviders', Mandatory = $false)]
    [switch]$CheckAMSIProviders,
    [Parameter(ParameterSetName = 'EnableAMSI', Mandatory = $false)]
    [switch]$EnableAMSI,
    [Parameter(ParameterSetName = 'DisableAMSI', Mandatory = $false)]
    [switch]$DisableAMSI,
    [Parameter(ParameterSetName = 'CheckStatus', Mandatory = $false)]
    [switch]$CheckStatus,
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $false)]
    [switch]$RestartIIS
)

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\Shared\Confirm-ExchangeShell.ps1

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

function CheckExchangeAndWindowsVersionsSupportedByAMSI {
    $E16orLaterMBXServers = Get-ExchangeServer | Where-Object { $_.IsMailboxServer -and $_.IsE15OrLater -and $_.AdminDisplayVersion.Minor -gt 0 } | Select-Object Name
    if ( $E16orLaterMBXServers.Count -eq 0 ) {
        Write-Output $msgNewLine
        Write-Warning "AMSI integration only applies to Exchange 2016 or later but we do not found anyone in the organization."
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    $E15orOlderMBXServers = Get-ExchangeServer | Where-Object { $_.IsMailboxServer -and ( -not $_.IsE15OrLater -or $_.AdminDisplayVersion.Minor -eq 0 ) } | Select-Object Name
    foreach ( $server in $E15orOlderMBXServers.Name ) {
        Write-Warning "AMSI does not apply on $server because it is Exchange 2013 or older"
    }

    $hasWindows2016orHigher = $false
    $hasWindows2012R2orLower = $false
    foreach ( $server in $E16orLaterMBXServers.Name ) {
        $temp = $null
        $temp = Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ( $temp ) {
            if ( $temp.Version.Split('.')[0] -ge 10 ) {
                $hasWindows2016orHigher = $true
            } else {
                $hasWindows2012R2orLower = $true
                Write-Warning "AMSI does not apply on $server because it is Windows 2012 R2 or older"
            }
        }
    }

    if ( -not $hasWindows2016orHigher ) {
        Write-Output $msgNewLine
        Write-Warning "We were not able to find any Exchange server 2016 or newest in a Windows 2016 or newest."
        Write-Warning "AMSI only works in Exchange 2016 or newest with Windows 2016 or newest."
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
    }

    if ( $hasWindows2012R2orLower ) {
        Write-Output $msgNewLine
        Write-Warning "We found Exchange servers running Windows older than Windows 2016."
        Write-Warning "AMSI only works in Exchange 2016 or newest with Windows 2016 or newest."
        Write-Warning "It will only applies in the newest versions."
        Start-Sleep -Seconds 2
    }
}

function CheckWindowsVersionIsW16orOlder {
    param(
        [string]$ExchangeServerFQDN
    )
    $temp = $null
    if ($ExchangeServerFQDN) {
        $temp = Get-CimInstance -ComputerName $ExchangeServerFQDN -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    } else {
        $temp = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    }
    if ( $temp ) {
        if ( $temp.Version.Split('.')[0] -lt 10 ) {
            Write-Output $msgNewLine
            Write-Warning "AMSI integration only applies to Windows 2016 or older."
            $Error.Clear()
            Start-Sleep -Seconds 2
            exit
        }
    } else {
        Write-Output $msgNewLine
        Write-Warning "We could not get Windows version."
        Write-Warning "AMSI integration only applies to Windows 2016 or older."
        $Error.Clear()
        Start-Sleep -Seconds 2
        exit
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

    if ( $TestAMSI -or $EnableAMSI -or $DisableAMSI) {
        $exchangeShell = Confirm-ExchangeShell
        if (-not($exchangeShell.ShellLoaded)) {
            Write-Warning "Failed to load Exchange Shell Module..."
            exit
        }
    }

    $dateTime = Get-Date
    $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($ExchangeServerFQDN) {
        $isE16orNewest = $null
        $isE16orNewest = Get-ExchangeServer $ExchangeServerFQDN | Where-Object { $_.IsMailboxServer -and $_.IsE15OrLater -and $_.AdminDisplayVersion.Minor -gt 0 }
        if ( $null -eq $isE16orNewest ) {
            Write-Output $msgNewLine
            Write-Warning "AMSI integration only applies to Exchange 2016 or older."
            $Error.Clear()
            Start-Sleep -Seconds 2
            exit
        }

        CheckWindowsVersionIsW16orOlder -ExchangeServerFQDN $ExchangeServerFQDN

        try {
            if ($IgnoreSSL) {
                SetCertificateValidationBehavior -Ignore
            }

            $CookieContainer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $Cookie = New-Object System.Net.Cookie("X-BEResource", "a]@$($ExchangeServerFQDN):444/ecp/proxyLogon.ecp#~1941997017", "/", "$ExchangeServerFQDN")
            $CookieContainer.Cookies.Add($Cookie)
            Invoke-WebRequest https://$ExchangeServerFQDN/ecp/x.js -Method POST -Headers @{"Host" = "$ExchangeServerFQDN" } -WebSession $CookieContainer
        } catch [System.Net.WebException] {
            if ($_.Exception.Message -notlike "*: (400)*") {
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
                $msgCheckLogs = "Check your log files located in " + $installPath + "Logging\HttpRequestFiltering\"
                Write-Output $msgCheckLogs
                $msgDetectedTimeStamp = "for a Detected result around " + $dateTime.ToUniversalTime()
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
        CheckWindowsVersionIsW16orOlder
        $AMSI = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -Recurse
        $AMSI -match '[0-9A-Fa-f\-]{36}' | Out-Null
        $Matches.Values | ForEach-Object { Get-ChildItem "HKLM:\SOFTWARE\Classes\ClSid\{$_}" | Format-Table -AutoSize }
    }

    $getSO = $null
    if ($EnableAMSI) {
        CheckExchangeAndWindowsVersionsSupportedByAMSI
        $getSO = Get-SettingOverride -Identity DisablingAMSIScan -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $_.Reason -eq 'Disabled via CSS-Exchange Script' }
        if ( $null -eq $getSO ) {
            Write-Warning "AMSI is NOT disabled by CSS-Exchange Script on Exchange configuration"
        } else {
            Remove-SettingOverride -Identity DisablingAMSIScan -Confirm:$false
            Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
            Write-Warning "Remember to restart IIS for this to take affect. You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
        }
        return
    }

    if ($DisableAMSI) {
        CheckExchangeAndWindowsVersionsSupportedByAMSI
        $getSO = Get-SettingOverride -Identity DisablingAMSIScan -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $_.Reason -eq 'Disabled via CSS-Exchange Script' }
        if ( $null -eq $getSO ) {
            New-SettingOverride -Name DisablingAMSIScan -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script"
            Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
            Write-Warning "Remember to restart IIS for this to take affect. You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
        } else {
            Write-Warning "AMSI is alredy disabled on Exchange configuration"
        }
        return
    }

    if ($CheckStatus) {
        CheckExchangeAndWindowsVersionsSupportedByAMSI
        $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' }
        if ( $null -eq $getSO ) {
            Write-Host "AMSI is Enabled for Exchange. We did not find any Settings Override that remove AMSI"
        } else {
            Write-Host "AMSI is Disabled by $($getSO.Identity) SettingOverride"
        }
        return
    }

    if ($RestartIIS) {
        Restart-Service -Name W3SVC, WAS -Force
        return
    }
}

Test-AMSI
