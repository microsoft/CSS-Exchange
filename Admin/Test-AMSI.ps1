# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#

.SYNOPSIS
	The Windows AntiMalware Scan Interface (AMSI) is a versatile standard that allows applications and services to integrate with any AntiMalware product present on a machine. Seeing that Exchange administrators might not be familiar with AMSI, we wanted to provide a script that would make life a bit easier to test, enable, disable, or Check your AMSI Providers.
.DESCRIPTION
	The Windows AntiMalware Scan Interface (AMSI) is a versatile standard that allows applications and services to integrate with any AntiMalware product present on a machine. Seeing that Exchange administrators might not be familiar with AMSI, we wanted to provide a script that would make life a bit easier to test, enable, disable, or Check your AMSI Providers.
.PARAMETER TestAMSI
	If you want to test to see if AMSI integration is working. You can use a server, server list or FQDN of load balanced array of Client Access servers.
.PARAMETER IgnoreSSL
    If you need to test and ignoring the certificate check.
.PARAMETER CheckAMSIConfig
    If you want to see what AMSI Providers are installed. You can combine with ServerList, AllServers or Sites.
.PARAMETER EnableAMSI
    If you want to enable AMSI. Without any additional parameter it will apply at Organization Level. If combine with ServerList, AllServers or Sites it will apply at server level.
.PARAMETER DisableAMSI
    If you want to disable AMSI. Without any additional parameter it will apply at Organization Level. If combine with ServerList, AllServers or Sites it will apply at server level.
.PARAMETER RestartIIS
    If you want to restart the Internet Information Services (IIS). You can combine with ServerList, AllServers or Sites.
.PARAMETER Force
    If you want to restart the Internet Information Services (IIS) without confirmation.
.PARAMETER ServerList
    If you want to apply to some specific servers.
.PARAMETER AllServers
    If you want to apply to all server.
.PARAMETER Sites
    If you want to apply to all server on a sites or list of sites.


.EXAMPLE
    .\Test-AMSI.ps1 mail.contoso.com
    If you want to test to see if AMSI integration is working in a LB Array

.EXAMPLE
    .\Test-AMSI.ps1 -ServerList server1, server2
    If you want to test to see if AMSI integration is working in list of servers.

.EXAMPLE
    .\Test-AMSI.ps1 -AllServers
    If you want to test to see if AMSI integration is working in all server.

.EXAMPLE
    .\Test-AMSI.ps1 -AllServers -Sites Site1, Site2
    If you want to test to see if AMSI integration is working in all server in a list of sites.

.EXAMPLE
    .\Test-AMSI.ps1 -IgnoreSSL
    If you need to test and ignoring the certificate check.

.EXAMPLE
    .\Test-AMSI.ps1 -CheckAMSIProviders
    If you want to see what AMSI Providers are installed on the local machine.

.EXAMPLE
    .\Test-AMSI.ps1 -EnableAMSI
    If you want to enable AMSI at organization level.

.EXAMPLE
    .\Test-AMSI.ps1 -EnableAMSI -ServerList Exch1, Exch2
    If you want to enable AMSI in an Exchange Server or Server List at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -EnableAMSI -AllServers
    If you want to enable AMSI in all Exchange Server at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -EnableAMSI -AllServers -Sites Site1, Site2
    If you want to enable AMSI in all Exchange Server in a site or sites at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -DisableAMSI
    If you want to disable AMSI on the Exchange Server.

.EXAMPLE
    .\Test-AMSI.ps1 -DisableAMSI -ServerList Exch1, Exch2
    If you want to disable AMSI in an Exchange Server or Server List at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -DisableAMSI -AllServers
    If you want to disable AMSI in all Exchange Server at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -DisableAMSI -AllServers -Sites Site1, Site2
    If you want to disable AMSI in all Exchange Server in a site or sites at server level.

.EXAMPLE
    .\Test-AMSI.ps1 -RestartIIS
    If you want to restart the Internet Information Services (IIS).

.EXAMPLE
    .\Test-AMSI.ps1 -RestartIIS -Force
    If you want to restart the Internet Information Services (IIS) without confirmation.

#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "TestAMSI", HelpUri = "https://microsoft.github.io/CSS-Exchange/Admin/Test-AMSI/")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Used Get-WmiObject just in case Get-CimInstance does not get the Windows version as a fallback.')]
param(
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $false)]
    [Parameter(ParameterSetName = 'TestAMSIAll', Mandatory = $false)]
    [switch]$TestAMSI,
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $false)]
    [Parameter(ParameterSetName = 'TestAMSIAll', Mandatory = $false)]
    [switch]$IgnoreSSL,
    [Parameter(ParameterSetName = 'CheckAMSIConfig', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CheckAMSIConfigAll', Mandatory = $true)]
    [switch]$CheckAMSIConfig,
    [Parameter(ParameterSetName = 'EnableAMSI', Mandatory = $true)]
    [Parameter(ParameterSetName = 'EnableAMSIAll', Mandatory = $true)]
    [switch]$EnableAMSI,
    [Parameter(ParameterSetName = 'DisableAMSI', Mandatory = $true)]
    [Parameter(ParameterSetName = 'DisableAMSIAll', Mandatory = $true)]
    [switch]$DisableAMSI,
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RestartIISAll', Mandatory = $true)]
    [switch]$RestartIIS,
    [Alias("ExchangeServerFQDN")]
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $false, ValueFromPipeline = $true)]
    [Parameter(ParameterSetName = 'EnableAMSI', Mandatory = $false, ValueFromPipeline = $true)]
    [Parameter(ParameterSetName = 'DisableAMSI', Mandatory = $false, ValueFromPipeline = $true)]
    [Parameter(ParameterSetName = 'CheckAMSIConfig', Mandatory = $false, ValueFromPipeline = $true)]
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$ServerList = $null,
    [Parameter(ParameterSetName = 'TestAMSIAll', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CheckAMSIConfigAll', Mandatory = $true)]
    [Parameter(ParameterSetName = 'EnableAMSIAll', Mandatory = $true)]
    [Parameter(ParameterSetName = 'DisableAMSIAll', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RestartIISAll', Mandatory = $true)]
    [switch]$AllServers,
    [Parameter(ParameterSetName = 'TestAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'CheckAMSIConfigAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'EnableAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'DisableAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'RestartIISAll', Mandatory = $false)]
    [string[]]$Sites = $null,
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $false)]
    [Parameter(ParameterSetName = 'RestartIISAll', Mandatory = $false)]
    [switch]$Force
)

begin {

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
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\Shared\Confirm-ExchangeShell.ps1

    function CheckServerAMSI {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ExchangeServer,
            [Parameter(Mandatory = $false)]
            [switch]$isServer
        )

        try {
            $CookieContainer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $Cookie = New-Object System.Net.Cookie("X-BEResource", "a]@$($ExchangeServer):444/ecp/proxyLogon.ecp#~1941997017", "/", "$ExchangeServer")
            $CookieContainer.Cookies.Add($Cookie)
            $testTime = Get-Date
            Write-Host "Starting test at $($testTime -f "yyyy-MM-dd HH:mm:ss")"
            if ($IgnoreSSL -and ![System.Net.ServicePointManager]::ServerCertificateValidationCallback ) {
                [ServerCertificateValidationBehavior]::Ignore()
            }
            Invoke-WebRequest https://$ExchangeServer/ecp/x.js -Method POST -Headers @{"Host" = "$ExchangeServer" } -WebSession $CookieContainer
        } catch [System.Net.WebException] {
            $Message = ($_.Exception.Message).ToString().Trim()
            $currentForegroundColor = $host.ui.RawUI.ForegroundColor
            if ( $_.Exception.Message -eq "The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.") {
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output $Message
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "You could use the -IgnoreSSL parameter"
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
            } elseif ($_.Exception.Message -eq "The remote server returned an error: (400) Bad Request.") {
                $host.ui.RawUI.ForegroundColor = "Green"
                Write-Output "We sent an test request to the ECP Virtual Directory of the server requested"
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "The remote server returned an error: (400) Bad Request"
                $host.ui.RawUI.ForegroundColor = "Green"
                $bar = ""
                1..($Host.UI.RawUI.WindowSize.Width) | ForEach-Object { $bar += "-" }
                Write-Output $bar
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "This may be indicative of a potential block from AMSI"
                $host.ui.RawUI.ForegroundColor = "Green"
                $msgCheckLogs = "You can check your log files located in %ExchangeInstallPath%\Logging\HttpRequestFiltering\"
                Write-Output $msgCheckLogs
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
                $msgDetectedTimeStamp = "You should find result around $((Get-Date).ToUniversalTime().ToString("M/d/yyy h:mm:ss tt")) UTC"
                Write-Output $msgDetectedTimeStamp
                if ( $isServer ) {
                    Write-Output ""
                    Write-Host "Checking logs on $server at $($testTime.ToString("M/d/yyy h:mm:ss tt"))"
                    $HttpRequestFilteringLogFolder = $null
                    if ( $server.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
                        $HttpRequestFilteringLogFolder = Join-Path $env:ExchangeInstallPath "Logging\HttpRequestFiltering\"
                    } else {
                        $remoteExchangePath = (Invoke-Command -ComputerName $server -ScriptBlock { (Get-ChildItem Env:ExchangeInstallPath).Value } -ErrorAction SilentlyContinue -ErrorVariable InvokeError)
                        if ( $remoteExchangePath ) {
                            $HttpRequestFilteringLogFolder = Join-Path "\\$server\$($remoteExchangePath.Replace(':','$'))" "Logging\HttpRequestFiltering\"
                        } else {
                            Write-Warning "Cannot get Remote Exchange installation path on $server"
                        }
                    }
                    if ( Test-Path $HttpRequestFilteringLogFolder -PathType Container ) {
                        $file = $null
                        $timeout = (Get-Date).AddMinutes(1)
                        $detected = $false
                        do {
                            $file = $null
                            Get-ChildItem $HttpRequestFilteringLogFolder | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -Property * | Out-Null
                            $file = Get-ChildItem $HttpRequestFilteringLogFolder -Filter "HttpRequestFiltering_*.log" | Where-Object { $_.LastWriteTime -ge $testTime }
                            if ( $file ) {
                                $csv = Import-Csv $file.FullName
                                foreach ($line in $csv) {
                                    $DateTime = $null
                                    try {
                                        $DateTime = [DateTime]::ParseExact($line.DateTime, 'M/d/yyyy h:mm:ss tt', $null)
                                    } catch {
                                        Write-Verbose ("We could not parse the date time on: {0}" -f $line)
                                    }
                                    if ( $DateTime ) {
                                        $marginTime = New-TimeSpan -Seconds 5
                                        if ($testTime.ToUniversalTime().Subtract($DateTime) -lt $marginTime -and $testTime.ToUniversalTime().Subtract($DateTime) -gt - $marginTime ) {
                                            if ( $line.UrlHost.ToLower() -eq $server.ToLower() -and $line.UrlStem.ToLower() -eq '/ecp/x.js'.ToLower() -and $line.ScanResult.ToLower() -eq 'Detected'.ToLower() ) {
                                                Write-Output ""
                                                Write-Host "We found a detection in HttpRequestFiltering logs: " -ForegroundColor Green
                                                Write-Host "$line"
                                                $detected = $true
                                            }
                                        }
                                    }
                                }
                            }
                            Start-Sleep -Seconds 2
                        } while ( ( -not $detected ) -and ((Get-Date) -lt $timeout) )
                        if ((Get-Date) -ge $timeout) {
                            Write-Warning  "We have not found activity on the server in the last minute."
                        }
                        if ( -not $detected ) {
                            Write-Warning "We have not found a detection."
                        }
                    } else {
                        Write-Host "We could not access HttpRequestFiltering folder on $server" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Check your log files located in %ExchangeInstallPath%\Logging\HttpRequestFiltering\ in all server that provide $server endpoint"
                }
            } elseif ( $_.Exception.Message -eq "The remote server returned an error: (500) Internal Server Error.") {
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output $msgNewLine
                Write-Output $Message
                Write-Output $msgNewLine
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "If you are using Microsoft Defender, RealTime protection could be disabled or then AMSI may be disabled."
                Write-Output "If you are using a 3rd Party AntiVirus Product that may not be AMSI capable (Please Check with your AntiVirus Provider for Exchange AMSI Support)"
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
            } elseif ( $_.Exception.Message.StartsWith("The remote name could not be resolved:") ) {
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output $msgNewLine
                Write-Output $Message
                Write-Output $msgNewLine
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
            } else {
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output $msgNewLine
                Write-Output $Message
                Write-Output $msgNewLine
                $host.ui.RawUI.ForegroundColor = "Yellow"
                Write-Output "If you are using Microsoft Defender, RealTime protection could be disabled or then AMSI may be disabled."
                Write-Output "If you are using a 3rd Party AntiVirus Product that may not be AMSI capable (Please Check with your AntiVirus Provider for Exchange AMSI Support)"
                $host.ui.RawUI.ForegroundColor = $currentForegroundColor
            }
        } finally {
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
        Write-Host "Ended test at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")"
        try {
            Invoke-WebRequest https://$ExchangeServer -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Verbose "We could not connect to https://$ExchangeServer"
        }
    }

    function GetWindowsMayorVersion {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ExchangeServer
        )

        if ( $ExchangeServer.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
            [System.Environment]::OSVersion.Version.Major
        } else {
            $temp = $null
            $temp = Get-CimInstance -ComputerName $ExchangeServer -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ( $null -eq $temp ) {
                $temp = Get-WmiObject -ComputerName $ExchangeServer -Query 'Select Version from Win32_OperatingSystem' -ErrorAction SilentlyContinue
            }
            if ( $temp ) {
                $temp.Version.Split('.')[0]
            } else {
                0
            }
        }
    }

    function CheckAMSIProviders {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ExchangeServer
        )

        $AMSIProviders = $null
        Write-Output $msgNewLine
        if ( $ExchangeServer.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
            Write-Host "Checking local AMSI Provider on $ExchangeServer"
            $AMSIProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -Recurse -ErrorAction SilentlyContinue
        } else {
            Write-Host "Checking remote AMSI Provider on $ExchangeServer"
            $AMSIProviders = Invoke-Command -ComputerName $ExchangeServer -ScriptBlock { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -Recurse -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue -ErrorVariable InvokeError
            if ( $InvokeError ) {
                Write-Warning "We could not connect with server $ExchangeServer"
                return
            }
        }
        if ( $null -eq $AMSIProviders ) {
            Write-Warning "We did not find any AMSI Provider"
        } else {
            foreach ( $provider in $AMSIProviders) {
                $provider -match '[0-9A-Fa-f\-]{36}' | Out-Null
                foreach ($m in $Matches.Values ) {
                    $key = "HKLM:\SOFTWARE\Classes\ClSid\{$m}"
                    Write-Output $msgNewLine
                    if ( $ExchangeServer.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
                        Write-Host "Local AMSI Providers detection:" -ForegroundColor Green
                        $providers = $null
                        $providers = Get-ChildItem $key -ErrorAction SilentlyContinue
                        if ($providers) {
                            $providers | Format-Table -AutoSize
                            $path = $null
                            $path = ($providers | Where-Object { $_.PSChildName -eq 'InprocServer32' } ).GetValue('')
                            if ( $path ) {
                                $WindowsDefenderPath = $path.Substring(1, $path.LastIndexOf("\"))
                                if ( $WindowsDefenderPath -like '*Windows Defender*') {
                                    Write-Host "Windows Defender with AMSI integration found." -ForegroundColor Green
                                    $checkCmdLet = $null
                                    $checkCmdLet = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
                                    if ($null -eq $checkCmdLet) {
                                        Write-Warning "Get-MpComputerStatus cmdLet is not available"
                                    } else {
                                        if ( (Get-MpComputerStatus).RealTimeProtectionEnabled ) {
                                            Write-Host "Windows Defender has Real Time Protection Enabled" -ForegroundColor Green
                                        } else {
                                            Write-Warning "Windows Defender has Real Time Protection Disabled"
                                        }
                                    }
                                    Write-Host "It should be version 1.1.18300.4 or newest."
                                    if ( Test-Path $WindowsDefenderPath -PathType Container ) {
                                        $folder = Get-ChildItem  $WindowsDefenderPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                        $process = Join-Path $folder.FullName "MpCmdRun.exe"
                                        if ( Test-Path $process -PathType Leaf ) {
                                            $DefenderVersion = (& $process -SignatureUpdate | Where-Object { $_.StartsWith('Engine Version:') }).Split(' ')[2]
                                            if ( [int]$DefenderVersion.Split('.')[0] -gt 1 -or
                                        ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -gt 1 ) -or
                                        ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -eq 1 -and [int]$DefenderVersion.Split('.')[2] -gt 18300 ) -or
                                        ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -eq 1 -and [int]$DefenderVersion.Split('.')[2] -eq 18300 -and [int]$DefenderVersion.Split('.')[3] -ge 4) ) {
                                                Write-Host "Windows Defender version supported for AMSI: $DefenderVersion" -ForegroundColor Green
                                            } else {
                                                Write-Warning  "Windows Defender version Non-supported for AMSI: $DefenderVersion"
                                            }
                                        } else {
                                            Write-Warning  "We did not find Windows Defender MpCmdRun.exe."
                                        }
                                    } else {
                                        Write-Warning "We did not find Windows Defender Path."
                                    }
                                } else {
                                    Write-Warning "It is not Windows Defender AV, check with your provider."
                                }
                            } else {
                                Write-Warning "We did not find AMSI providers."
                            }
                        } else {
                            Write-Host "We did not find any AMSI provider" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Remote AMSI Providers detection:" -ForegroundColor Green
                        $providers = $null
                        $providers = Invoke-Command -ComputerName $ExchangeServer -ScriptBlock { Get-ChildItem $using:key -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue | Format-Table -AutoSize
                        if ($providers) {
                            $providers | Format-Table -AutoSize
                            Invoke-Command -ComputerName $server -ScriptBlock {
                                $providers = Get-ChildItem $using:key -ErrorAction SilentlyContinue
                                $path = $null
                                $path = ($providers | Where-Object { $_.PSChildName -eq 'InprocServer32' } ).GetValue('')
                                if ( $path ) {
                                    $WindowsDefenderPath = $path.Substring(1, $path.LastIndexOf("\"))
                                    if ( $WindowsDefenderPath -like '*Windows Defender*') {
                                        Write-Host "Windows Defender with AMSI integration found." -ForegroundColor Green
                                        $checkCmdLet = $null
                                        $checkCmdLet = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
                                        if ($null -eq $checkCmdLet) {
                                            Write-Warning "Get-MpComputerStatus cmdLet is not available"
                                        } else {
                                            if ( (Get-MpComputerStatus).RealTimeProtectionEnabled ) {
                                                Write-Host "Windows Defender has Real Time Protection Enabled" -ForegroundColor Green
                                            } else {
                                                Write-Warning "Windows Defender has Real Time Protection Disabled"
                                            }
                                        }
                                        Write-Host "It should be version 1.1.18300.4 or newest."
                                        if ( Test-Path $WindowsDefenderPath -PathType Container ) {
                                            $folder = Get-ChildItem  $WindowsDefenderPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                            $process = Join-Path $folder.FullName "MpCmdRun.exe"
                                            if ( Test-Path $process -PathType Leaf ) {
                                                $DefenderVersion = (& $process -SignatureUpdate | Where-Object { $_.StartsWith('Engine Version:') }).Split(' ')[2]
                                                if ( [int]$DefenderVersion.Split('.')[0] -gt 1 -or
                                            ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -gt 1 ) -or
                                            ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -eq 1 -and [int]$DefenderVersion.Split('.')[2] -gt 18300 ) -or
                                            ( [int]$DefenderVersion.Split('.')[0] -eq 1 -and [int]$DefenderVersion.Split('.')[1] -eq 1 -and [int]$DefenderVersion.Split('.')[2] -eq 18300 -and [int]$DefenderVersion.Split('.')[3] -ge 4) ) {
                                                    Write-Host "Windows Defender version supported for AMSI: $DefenderVersion" -ForegroundColor Green
                                                } else {
                                                    Write-Warning  "Windows Defender version Non-supported for AMSI: $DefenderVersion"
                                                }
                                            } else {
                                                Write-Warning  "We did not find Windows Defender MpCmdRun.exe."
                                            }
                                        } else {
                                            Write-Warning "We did not find Windows Defender Path."
                                        }
                                    } else {
                                        Write-Warning "It is not Windows Defender AV, check with your provider."
                                    }
                                } else {
                                    Write-Warning "We did not find AMSI providers."
                                }
                            } -ErrorAction SilentlyContinue
                        } else {
                            Write-Host "We did not find any AMSI provider" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }

    function CheckAMSIConfig {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ExchangeServer
        )
        $getSO = $null
        $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $_.Server -contains $ExchangeServer }
        if ( $getSO ) {
            $getSO | Out-Host
            if ( $getSO.Status -eq "Accepted" ) {
                Write-Warning "AMSI is Disabled by $($getSO.Identity) SettingOverride for $ExchangeServer"
            } else {
                Write-Host "We found SettingOverride for $ExchangeServer ($($getSO.Identity))"
                Write-Warning "The Status of $($getSO.Identity) is not Accepted. Should not apply for $ExchangeServer."
            }
        } else {
            Write-Output ""
            Write-Host "AMSI is Enabled on Server $ExchangeServer. We did not find any Settings Override that remove AMSI." -ForegroundColor Green

            $FEEcpWebConfig = $null
            $CAEEcpWebConfig = $null
            if ( $ExchangeServer.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
                if ( $env:ExchangeInstallPath ) {
                    $FEEcpWebConfig = Join-Path $env:ExchangeInstallPath "FrontEnd\HttpProxy\ecp\web.config"
                    $CAEEcpWebConfig = Join-Path $env:ExchangeInstallPath "ClientAccess\ecp\web.config"
                }
            } else {
                $remoteExchangePath = (Invoke-Command -ComputerName $ExchangeServer -ScriptBlock { (Get-ChildItem Env:ExchangeInstallPath).Value }  -ArgumentList $env:ExchangeInstallPath -ErrorAction SilentlyContinue -ErrorVariable InvokeError)
                if ( $remoteExchangePath ) {
                    $FEEcpWebConfig = Join-Path "\\$ExchangeServer\$($remoteExchangePath.Replace(':','$'))" "FrontEnd\HttpProxy\ecp\web.config"
                    $CAEEcpWebConfig = Join-Path "\\$ExchangeServer\$($remoteExchangePath.Replace(':','$'))" "ClientAccess\ecp\web.config"
                }
            }

            if ( $FEEcpWebConfig -and $CAEEcpWebConfig) {
                if ( Test-Path $FEEcpWebConfig -PathType Leaf) {
                    $FEFilterModule = $null
                    $FEFilterModule = Get-Content $FEEcpWebConfig | Where-Object { $_ -match '<add name="HttpRequestFilteringModule" type="Microsoft.Exchange.HttpRequestFiltering.HttpRequestFilteringModule, Microsoft.Exchange.HttpRequestFiltering, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"' }
                    Write-Output ""
                    if ( $FEFilterModule ) {
                        Write-Host "We found HttpRequestFilteringModule on FrontEnd ECP web.config" -ForegroundColor Green
                        Write-Host "on: %ExchangeInstallPath%FrontEnd\HttpProxy\ecp\web.config"
                    } else {
                        Write-Warning "We did not find HttpRequestFilteringModule on FrontEnd ECP web.config"
                        Write-Warning "on: %ExchangeInstallPath%FrontEnd\HttpProxy\ecp\web.config"
                    }
                } else {
                    Write-Warning "We did not find web.config for FrontEnd ECP"
                    Write-Warning "on: %ExchangeInstallPath%FrontEnd\HttpProxy\ecp\web.config"
                }

                if ( Test-Path $FEEcpWebConfig -PathType Leaf) {
                    $CEFilterModule = $null
                    $CEFilterModule = Get-Content $CAEEcpWebConfig | Where-Object { $_ -match '<add name="HttpRequestFilteringModule" type="Microsoft.Exchange.HttpRequestFiltering.HttpRequestFilteringModule, Microsoft.Exchange.HttpRequestFiltering, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"' }
                    Write-Output ""
                    if ( $CEFilterModule ) {
                        Write-Host "We found HttpRequestFilteringModule on ClientAccess ECP web.config" -ForegroundColor Green
                        Write-Host "on %ExchangeInstallPath%ClientAccess\ecp\web.config"
                    } else {
                        Write-Warning "We did not find HttpRequestFilteringModule on ClientAccess ECP web.config"
                        Write-Warning "on %ExchangeInstallPath%ClientAccess\ecp\web.config"
                    }
                } else {
                    Write-Warning "We did not find web.config for ClientAccess ECP"
                    Write-Warning "on %ExchangeInstallPath%ClientAccess\ecp\web.config"
                }
            } else {
                Write-Host "We could not get FrontEnd or BackEnd Web.config path on $ExchangeServer." -ForegroundColor Red
            }
        }
    }

    $msgNewLine = "`n"
    if (-not (Confirm-Administrator)) {
        Write-Output $msgNewLine
        Write-Warning "This script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator and try again."
        exit
    }

    $exchangeShell = Confirm-ExchangeShell
    if (-not($exchangeShell.ShellLoaded)) {
        Write-Output $msgNewLine
        Write-Warning "Failed to load Exchange Shell Module..."
        exit
    }
}

process {
    $filterList = @()

    if ( $PSCmdlet.ParameterSetName -eq "TestAMSI" -or $PSCmdlet.ParameterSetName -eq "TestAMSIAll" ) {
        $TestAMSI = $true
    }

    if ( $null -eq $ServerList -and ( $RestartIIS -or $CheckAMSIConfig -or $TestAMSI ) -and ( -not $AllServers ) ) {
        $ServerList = $env:COMPUTERNAME
    }

    Write-Host "AMSI only support on Exchange 2016 CU21 or newer, Exchange 2019 CU10 or newer and running on Windows 2016 or newer" -ForegroundColor Green
    $SupportedExchangeServers = Get-ExchangeServer | Where-Object { $_.IsClientAccessServer -and ( ($_.AdminDisplayVersion.Minor -eq 1 -and $_.AdminDisplayVersion.Build -ge 2308) -or ($_.AdminDisplayVersion.Minor -eq 2 -and $_.AdminDisplayVersion.Build -ge 922) ) } | Select-Object Name, Site
    if ($Sites) {
        $uniqueSites = $null
        $uniqueSites = $SupportedExchangeServers.Site.Name | Get-Unique
        foreach ($site in $Sites) {
            if ( $uniqueSites -notcontains $site ) {
                Write-Warning "We did not find site $site"
            }
        }
        $fullList = ( $SupportedExchangeServers | Where-Object { $Sites -contains $_.Site.Name } | Select-Object Name).Name
    } else {
        $fullList = ( $SupportedExchangeServers | Select-Object Name).Name
    }

    if ( $AllServers ) {
        foreach ($server in $fullList) {
            $serverName = $server.Split('.')[0]
            if ( $SupportedExchangeServers.Name -contains $serverName ) {
                $Version = GetWindowsMayorVersion -ExchangeServer $server
                if ( $Version -eq 0 ) {
                    Write-Warning "We could not get Windows version for $server."
                    Write-Warning "Try to run the script locally."
                } else {
                    if ( $Version -ge 10 ) {
                        $filterList += $serverName
                    } else {
                        Write-Warning "$server is not a Windows version with AMSI support."
                    }
                }
            } else {
                Write-Warning "$server is not an Exchange version with AMSI support."
            }
        }
    } else {
        foreach ($server in $ServerList) {
            $serverName = $server.Split('.')[0]
            if ( $fullList -contains $serverName ) {
                if ( $SupportedExchangeServers.Name -contains $serverName ) {
                    $Version = GetWindowsMayorVersion -ExchangeServer $server
                    if ( $Version -eq 0 ) {
                        Write-Warning "We could not get Windows version for $server."
                        Write-Warning "Try to run the script locally."
                    } else {
                        if ( $Version -ge 10 ) {
                            $filterList += $serverName
                        } else {
                            Write-Warning "$server is not a Windows version with AMSI support."
                        }
                    }
                } else {
                    Write-Warning "$server is not an Exchange version with AMSI support."
                }
            } else {
                Write-Warning "We did not find any Exchange server with name: $server"
                if ( $TestAMSI ) {
                    $filterList += $server
                }
            }
        }
    }

    if ( ( $filterList.count -gt 0 -or $TestAMSI -or
        ( ( $EnableAMSI -or $DisableAMSI) -and -not $ServerList ) ) -and
        $SupportedExchangeServers.count -gt 0 ) {

        if ($TestAMSI) {
            foreach ($server in $filterList) {
                Write-Output $msgNewLine
                Write-Host "Testing $($server):"
                if ( $fullList -contains $server ) {
                    CheckServerAMSI -ExchangeServer $server -isServer
                } else {
                    CheckServerAMSI -ExchangeServer $server
                }
            }
        }

        if ($CheckAMSIConfig) {
            if ($filterList) {
                foreach ( $server in $filterList) {
                    Write-Output $msgNewLine
                    Write-Output "Checking $($server):"
                    CheckAMSIProviders -ExchangeServer $server
                    CheckAMSIConfig -ExchangeServer $server
                }
            }
            Write-Output $msgNewLine
            $getSO = $null
            $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $null -eq $_.Server }
            if ( $getSO ) {
                $getSO | Out-Host
                if ( $getSO.Status -eq "Accepted" ) {
                    Write-Warning "AMSI is Disabled by $($getSO.Identity) SettingOverride at organization Level."
                } else {
                    Write-Host "We found SettingOverride for $ExchangeServer ($($getSO.Identity))"
                    Write-Warning "The Status of $($getSO.Identity) is not Accepted. Should not apply at organization Level."
                }
            } else {
                Write-Host "AMSI is Enabled for Exchange at Organization Level." -ForegroundColor Green
                Write-Host "We did not find any Settings Override that remove AMSI at organization Level."
            }
            Write-Output $msgNewLine
            Write-Host 'You can find additional information:'
            Write-Host 'https://techcommunity.microsoft.com/t5/exchange-team-blog/more-about-amsi-integration-with-exchange-server/ba-p/2572371' -ForegroundColor Cyan
        }

        $needsRefresh = 0
        if ($EnableAMSI) {
            $getSO = $null
            if ($filterList) {
                foreach ( $server in $filterList ) {
                    Write-Output $msgNewLine
                    $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $_.Server -contains $server }
                    if ( $null -eq $getSO ) {
                        Write-Host "We did not find Get-SettingOverride that disabled AMSI on $server"
                        Write-Warning "AMSI is NOT disabled on $server"
                    } else {
                        Write-Host "Removing SettingOverride $($getSO.Identity)"
                        $getSO | Out-Host
                        Remove-SettingOverride -Identity $getSO.Identity -Confirm:$false
                        Write-Warning "Enabled on $server"
                        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                        Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                        $needsRefresh++
                    }
                }
            } else {
                Write-Output $msgNewLine
                $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $null -eq $_.Server }
                if ( $null -eq $getSO ) {
                    Write-Host "We did not find Get-SettingOverride that disabled AMSI at Organization level"
                    Write-Warning "AMSI is NOT disabled on Exchange configuration at organization level"
                } else {
                    Write-Host "Removing SettingOverride $($getSO.Identity)"
                    $getSO | Out-Host
                    Remove-SettingOverride -Identity $getSO.Identity -Confirm:$false
                    Write-Warning "Enabled AMSI at Organization Level"
                    foreach ($server in $filterList) {
                        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                        Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                    }
                    $needsRefresh++
                }
            }
        }

        if ($DisableAMSI) {
            $getSO = $null
            if ($filterList) {
                foreach ($server in $filterList) {
                    Write-Output $msgNewLine
                    $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $_.Server -contains $server }
                    if ( $null -eq $getSO ) {
                        New-SettingOverride -Name "DisablingAMSIScan-$server" -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script" -Server $server
                        Write-Warning "Disabled on $server by DisablingAMSIScan-$server SettingOverride"
                        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                        Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                        $needsRefresh++
                    } else {
                        Write-Warning "AMSI is already disabled on Exchange configuration for $server by SettingOverride $($getSO.Identity)"
                    }
                }
            } else {
                Write-Output $msgNewLine
                $getSO = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object { $_.SectionName -eq 'HttpRequestFiltering' -and $_.Parameters -eq 'Enabled=False' -and $null -eq $_.Server }
                if ( $null -eq $getSO ) {
                    New-SettingOverride -Name DisablingAMSIScan-OrgLevel -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script"
                    Write-Warning "Disabled AMSI at Organization Level by DisablingAMSIScan-OrgLevel SettingOverride"
                    foreach ($server in $filterList) {
                        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                        Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                    }
                    $needsRefresh++
                } else {
                    Write-Warning "AMSI is already disabled on Exchange configuration by SettingOverride $($getSO.Identity)"
                }
            }
        }

        if ( $needsRefresh -gt 0 -and ($SupportedExchangeServers.Site.Name | Get-Unique).count -gt 1) {
            Write-Host ""
            Write-Warning "You have a multi site environment, confirm that all affected Exchange sites has replicated changes."
            Write-Host "You can push changes on your DCs with: repadmin /syncall /AdeP"
            Write-Host ""
            Write-Host "Remember to restart IIS to be effective."
            Write-Host "You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
        }

        if ( $RestartIIS ) {
            if ($filterList) {
                $yesToAll = $false
                $noToAll = $false

                if ( $Force -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "This command wil restart the following IIS servers: $filterList", $true, [ref]$yesToAll, [ref]$noToAll) ) {
                    foreach ($server in $filterList) {
                        Write-Output $msgNewLine
                        if ( $Force -or $filterList.Count -eq 1 -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "You will restart IIS on server $server", $true, [ref]$yesToAll, [ref]$noToAll) ) {
                            Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                            Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                            if ( $server.ToLower() -eq $env:COMPUTERNAME.ToLower() ) {
                                Write-Host "Restarting local IIS on $server"
                                Get-Service W3SVC, WAS | Restart-Service -Force
                            } else {
                                Write-Host "Restarting Remote IIS on $server"
                                Get-Service W3SVC, WAS -ComputerName $server | Restart-Service -Force
                            }
                            Write-Host "$server Restarted"
                        }
                    }
                }
            }
        }
    } else {
        Write-Warning "We did not find Exchange servers with AMSI support"
    }
    Write-Output $msgNewLine
}
