﻿# Copyright (c) Microsoft Corporation.
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
    .\Test-AMSI.ps1 CheckAMSIConfig
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
    [switch]$Force,
    [Parameter(ParameterSetName = 'TestAMSI', Mandatory = $false)]
    [Parameter(ParameterSetName = 'TestAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'CheckAMSIConfig', Mandatory = $false)]
    [Parameter(ParameterSetName = 'CheckAMSIConfigAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'EnableAMSI', Mandatory = $false)]
    [Parameter(ParameterSetName = 'EnableAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'DisableAMSI', Mandatory = $false)]
    [Parameter(ParameterSetName = 'DisableAMSIAll', Mandatory = $false)]
    [Parameter(ParameterSetName = 'RestartIIS', Mandatory = $false)]
    [Parameter(ParameterSetName = 'RestartIISAll', Mandatory = $false)]
    [switch]$SkipVersionCheck,
    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

begin {

    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\Shared\Invoke-ScriptBlockHandler.ps1
    . $PSScriptRoot\..\Shared\CertificateFunctions\Enable-TrustAnyCertificateCallback.ps1
    . $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\Shared\Get-ExchangeBuildVersionInformation.ps1
    . $PSScriptRoot\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Progress.ps1

    function Write-DebugLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
        }
    }

    function Write-HostLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
            $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
        }
    }

    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteProgressAction ${Function:Write-DebugLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    $LogFileName = "Test-AMSI"
    $StartDate = Get-Date
    $StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    $Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

    function SearchOnLogs {
        param(
            [Parameter(ParameterSetName = 'SearchHttpRequestFiltering', Mandatory = $true)]
            [switch]$SearchHttpRequestFiltering,
            [Parameter(ParameterSetName = 'SearchIIS', Mandatory = $true)]
            [switch]$SearchIIS,
            [Parameter(ParameterSetName = 'SearchIIS', Mandatory = $true)]
            [Parameter(ParameterSetName = 'SearchHttpRequestFiltering', Mandatory = $true)]
            [string]$Server,
            [Parameter(ParameterSetName = 'SearchHttpRequestFiltering', Mandatory = $true)]
            [string]$ExchangePath,
            [Parameter(ParameterSetName = 'SearchIIS', Mandatory = $true)]
            [Parameter(ParameterSetName = 'SearchHttpRequestFiltering', Mandatory = $true)]
            [string]$UrlStem
        )

        $LogFolder = $null
        $isDisabled = $false

        if ($SearchHttpRequestFiltering) {
            $OriginalLogFolder = Join-Path $ExchangePath "Logging\HttpRequestFiltering\"
            if ($Server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
                $LogFolder = $OriginalLogFolder
            } else {
                $LogFolder = "\\$Server\$($OriginalLogFolder.Replace(':','$'))"
            }
        }

        if ($SearchIIS) {
            $getIISLogPath = {
                $webSite = Get-Website "Default Web Site"
                $logPath = $webSite.logFile.directory
                $resolvedPath = [System.IO.Path]::GetFullPath([System.Environment]::ExpandEnvironmentVariables($logPath))
                "$resolvedPath\w3svc$($webSite.id)"
            }

            $OriginalLogFolder = $null
            $OriginalLogFolder = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock $getIISLogPath
            if ($OriginalLogFolder) {
                if ($server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $LogFolder = $OriginalLogFolder
                } else {
                    $LogFolder = "\\$server\$($OriginalLogFolder.Replace(':','$'))"
                }

                $getIISLogDisabled = { (Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\ecp" -Filter "system.webServer/httpLogging" -Name donTLog).Value }
                $isDisabled = (Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock $getIISLogDisabled)
                if ($isDisabled) {
                    Write-Host "We could not get IIS log for $Server because it is disabled" -ForegroundColor Yellow
                    return
                }
            } else {
                Write-Host "We could not get IIS log for $Server" -ForegroundColor Red
                return
            }
        }

        if ($LogFolder) {
            if (Test-Path -Path $LogFolder -PathType Container) {
                Write-Host "Looking for request $UrlStem on server $Server" -ForegroundColor Yellow
                if ($SearchIIS) {
                    Write-Host "IIS logs on Folder $OriginalLogFolder ..."
                } else {
                    Write-Host "HttpRequestFiltering logs on Folder $OriginalLogFolder ..."
                }

                if (Test-Path $LogFolder -PathType Container) {
                    $timeout1min = (Get-Date).AddMinutes(1)
                    $foundRequest = $false
                    do {
                        Start-Sleep -Seconds 1
                        $remainSeconds = ($timeout1min - (Get-Date)).Seconds
                        Write-Progress -Activity "Searching on logs ..." -Status "Max seconds Remaining" -SecondsRemaining $remainSeconds
                        $file = $null
                        $file = Get-ChildItem $LogFolder -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -Property *
                        $found = $file | Get-Content | Select-String $UrlStem
                        if ($found) {
                            Write-Host "We found the request on logs: " -ForegroundColor Green
                            Write-Host "$($found.Line)"
                            $foundRequest = $true
                            if ($SearchHttpRequestFiltering) {
                                Write-Host " "
                                Write-Host "Request blocked by server: $Server from AMSI" -ForegroundColor Green
                                Write-Host " "
                            }
                        }
                    } while ((-not $foundRequest) -and ($remainSeconds -gt 0))
                    Write-Progress -Activity "Searching on logs ..." -Completed
                    if (-not $foundRequest) {
                        Write-Warning "We have not found the request on FrontEnd server: $Server." -ForegroundColor Red
                        if ($SearchHttpRequestFiltering) {
                            Write-Host "Server: $Server has not record on HttpRequestFiltering log" -ForegroundColor Red
                        }
                        Write-Host " "
                    }
                } else {
                    Write-Host "Error accessing $LogFolder on $Server" -ForegroundColor Red
                }
            } else {
                Write-Host "We could not access Logs folder on $Server" -ForegroundColor Red
            }
        } else {
            Write-Host "We could not get log folder for $Server" -ForegroundColor Yellow
        }
    }

    function HasWindowsVersionAmsiSupport {
        param(
            [Parameter(Mandatory = $true)]
            [string]$server
        )

        $Version
        $Version = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock { [System.Environment]::OSVersion.Version.Major }
        if ($Version) {
            if ($Version -ge 10) {
                return $true
            } else {
                Write-Host "$server is not a Windows version with AMSI support." -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "We could not get Windows version for $server." -ForegroundColor Red
            return $false
        }
    }

    function CheckServerAMSI {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Server
        )

        try {
            $CookieContainer = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $Cookie = New-Object System.Net.Cookie("X-BEResource", "a]@$($Server):444/ecp/proxyLogon.ecp#~1941997017", "/", "$Server")
            $CookieContainer.Cookies.Add($Cookie)
            if ($IgnoreSSL -and ![System.Net.ServicePointManager]::ServerCertificateValidationCallback) {
                Enable-TrustAnyCertificateCallback
            }

            $length = 10
            $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray()
            $randomString = -join ($characters | Get-Random -Count $length)
            $UrlStem = "/ecp/Test-$randomString.js"
            $urlRequest = "https://$Server$UrlStem"
            Write-Host "Test string: Test-$randomString"
            Write-Host " "
            Invoke-WebRequest -Uri $urlRequest -Method POST -Headers @{ "Host" = "$Server" } -WebSession $CookieContainer -DisableKeepAlive
        } catch [System.Net.WebException] {
            $Message = ($_.Exception.Message).ToString().Trim()
            $FEServer = $null
            if ($_.Exception.Response.Headers) {
                $FEServer = $_.Exception.Response.Headers["X-FEServer"]
                if ($FEServer) {
                    Write-Host "FrontEnd Detected: $FEServer" -ForegroundColor Green
                    Write-Host " "
                }
            }
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) {
                Write-Host " "
                Write-Host $Message -ForegroundColor Red
                Write-Host "You could use the -IgnoreSSL parameter" -ForegroundColor Yellow
            } elseif ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::ProtocolError -and
                $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::BadRequest ) {
                Write-Host " "
                Write-Host "The remote server returned an error: (400) Bad Request" -ForegroundColor Green
                Write-Host "This may be indicative of a potential block from AMSI" -ForegroundColor Green
                Write-Host " "
                if ($FEServer) {
                    if ($fullList -contains $FEServer) {
                        SearchOnLogs -SearchIIS -Server $FEServer -UrlStem $UrlStem
                        $getMSIInstallPathSB = { (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath }
                        $ExchangePath = $null
                        $ExchangePath = Invoke-ScriptBlockHandler -ComputerName $FEServer -ScriptBlock $getMSIInstallPathSB
                        if ($ExchangePath) {
                            SearchOnLogs -SearchHttpRequestFiltering -Server $FEServer -ExchangePath $ExchangePath -UrlStem $UrlStem
                        } else {
                            Write-Host "We could not get Exchange installation path on $FEServer" -ForegroundColor Red
                        }
                        Write-Host " "
                    } else {
                        Write-Host "FrontEnd server is not an Exchange Server" -ForegroundColor Red
                        Write-Host " "
                    }
                }
            } elseif ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::NameResolutionFailure) {
                Write-Host " "
                Write-Host $Message -ForegroundColor Red
                Write-Host " "
                Write-Host "We could not find the server requested. Please check the name of the server." -ForegroundColor Red
            } else {
                Write-Host " "
                Write-Host $Message -ForegroundColor Red
                Write-Host " "
                if ($fullList -contains $FEServer) {
                    SearchOnLogs -SearchIIS -Server $FEServer -UrlStem $UrlStem
                    Write-Host " "
                    Write-Host "Server: $FEServer do not detect bad Request, it has not triggered AMSI" -ForegroundColor Red
                    Write-Host " "
                    Write-Host "If you are using Microsoft Defender, RealTime protection could be disabled or then AMSI may be disabled." -ForegroundColor Yellow
                    Write-Host "If you are using a 3rd Party AntiVirus Product that may not be AMSI capable (Please Check with your AntiVirus Provider for Exchange AMSI Support)" -ForegroundColor Yellow
                } else {
                    if ($FEServer) {
                        Write-Host " "
                        Write-Host "FrontEnd server $FEServer is not an Exchange Server" -ForegroundColor Red
                        Write-Host " "
                    }
                }
            }
        } finally {
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                try {
                    Invoke-WebRequest https://$Server -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    Write-Verbose "We could not connect to https://$Server (Expected)"
                }
            }
        }
    }

    function CheckAMSIConfig {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ExchangeServer
        )

        Write-Host " "
        Write-Host "AMSI Providers detection:" -ForegroundColor Green

        $AMSIProvidersSB = {
            $AMSIProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -Recurse -ErrorAction SilentlyContinue
            if ($AMSIProviders) {
                Write-Host "Providers:"
                $providerCount = 0
                foreach ($provider in $AMSIProviders) {
                    Write-Host " "
                    Write-Host "Provider $($providerCount+1): $($provider.PSChildName)" -ForegroundColor DarkGreen
                    # when using -match we set the variable $Match when a true value is performed.
                    $foundMatch = $provider -match '[0-9A-Fa-f\-]{36}'
                    if ($foundMatch) {
                        foreach ($m in $Matches.Values) {
                            $key = "HKLM:\SOFTWARE\Classes\ClSid\{$m}"
                            $providers = $null
                            $providers = Get-ChildItem $key -ErrorAction SilentlyContinue
                            if ($providers) {
                                $providerCount++
                                $providers | Format-Table -AutoSize | Out-String | Write-Host
                                $path = $null
                                $path = ($providers | Where-Object { $_.PSChildName -eq 'InprocServer32' }).GetValue('')
                                if ($path) {
                                    $WindowsDefenderPath = $path.Substring(1, $path.LastIndexOf("\"))
                                    if ($WindowsDefenderPath -like '*Windows Defender*') {
                                        Write-Host "Windows Defender with AMSI integration found." -ForegroundColor Green
                                        $checkCmdLet = $null
                                        $checkCmdLet = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
                                        if ($null -eq $checkCmdLet) {
                                            Write-Warning "Get-MpComputerStatus cmdLet is not available"
                                        } else {
                                            if ((Get-MpComputerStatus).RealTimeProtectionEnabled) {
                                                Write-Host "Windows Defender has Real Time Protection Enabled" -ForegroundColor Green
                                            } else {
                                                Write-Host "Windows Defender has Real Time Protection Disabled" -ForegroundColor Red
                                            }
                                            Write-Host "It should be version 1.1.18300.4 or newest."
                                            if (Test-Path $WindowsDefenderPath -PathType Container) {
                                                $process = Join-Path -Path $WindowsDefenderPath -ChildPath "MpCmdRun.exe"
                                                if (Test-Path $process -PathType Leaf) {
                                                    $DefenderVersion = $null
                                                    $DefenderVersion = [System.Version]::new((& $process -SignatureUpdate | Where-Object { $_.StartsWith('Engine Version:') }).Split(' ')[2])
                                                    if ($DefenderVersion) {
                                                        if ($DefenderVersion -ge "1.1.18300.4") {
                                                            Write-Host "Windows Defender version supported for AMSI: $DefenderVersion" -ForegroundColor Green
                                                        } else {
                                                            Write-Host "Windows Defender version Non-supported for AMSI: $DefenderVersion" -ForegroundColor Red
                                                        }
                                                    } else {
                                                        Write-Host "We could not get Windows Defender version" -ForegroundColor Red
                                                    }
                                                } else {
                                                    Write-Host "We did not find Windows Defender MpCmdRun.exe." -ForegroundColor Red
                                                }
                                            } else {
                                                Write-Host "We did not find Windows Defender Path." -ForegroundColor Red
                                            }
                                        }
                                    } else {
                                        Write-Host "It is not Windows Defender AV, check with your provider." -ForegroundColor Red
                                    }
                                } else {
                                    Write-Host "We did not find AMSI providers." -ForegroundColor Red
                                }
                            } else {
                                Write-Host "We did not find $m ClSid registered" -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host "We did not find any ClSid on $($provider.PSChildName) AMSI provider." -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "We did not find any AMSI provider" -ForegroundColor Red
            }
        }

        Write-Host " "
        Write-Host "Checking AMSI Provider on $ExchangeServer"
        Write-Host " "
        Invoke-ScriptBlockHandler -ComputerName $ExchangeServer -ScriptBlock $AMSIProvidersSB

        $FEEcpWebConfig = $null
        $CAEEcpWebConfig = $null

        $getMSIInstallPathSB = { (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath }
        $ExchangePath = Invoke-ScriptBlockHandler -ComputerName $ExchangeServer -ScriptBlock $getMSIInstallPathSB

        if ($ExchangePath) {
            if ($ExchangeServer.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
                $FEEcpWebConfig = Join-Path $ExchangePath "FrontEnd\HttpProxy\ecp\web.config"
                $CAEEcpWebConfig = Join-Path $ExchangePath "ClientAccess\ecp\web.config"
            } else {
                $FEEcpWebConfig = Join-Path "\\$ExchangeServer\$($ExchangePath.Replace(':','$'))" "FrontEnd\HttpProxy\ecp\web.config"
                $CAEEcpWebConfig = Join-Path "\\$ExchangeServer\$($ExchangePath.Replace(':','$'))" "ClientAccess\ecp\web.config"
            }

            if ($FEEcpWebConfig -and $CAEEcpWebConfig) {
                if (Test-Path $FEEcpWebConfig -PathType Leaf) {
                    $FEFilterModule = $null
                    $FEFilterModule = Get-Content $FEEcpWebConfig | Select-String '<add name="HttpRequestFilteringModule" type="Microsoft.Exchange.HttpRequestFiltering.HttpRequestFilteringModule, Microsoft.Exchange.HttpRequestFiltering, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"'
                    Write-Host " "
                    if ($FEFilterModule) {
                        Write-Host "We found HttpRequestFilteringModule on FrontEnd ECP web.config" -ForegroundColor Green
                    } else {
                        Write-Host "We did not find HttpRequestFilteringModule on FrontEnd ECP web.config" -ForegroundColor Red
                    }
                } else {
                    Write-Host "We did not find web.config for FrontEnd ECP" -ForegroundColor Red
                }
                Write-Host "Path: $($ExchangePath)FrontEnd\HttpProxy\ecp\web.config"

                if (Test-Path $FEEcpWebConfig -PathType Leaf) {
                    $CEFilterModule = $null
                    $CEFilterModule = Get-Content $CAEEcpWebConfig | Select-String '<add name="HttpRequestFilteringModule" type="Microsoft.Exchange.HttpRequestFiltering.HttpRequestFilteringModule, Microsoft.Exchange.HttpRequestFiltering, Version=15.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"'
                    Write-Host " "
                    if ($CEFilterModule) {
                        Write-Host "We found HttpRequestFilteringModule on ClientAccess ECP web.config" -ForegroundColor Green
                    } else {
                        Write-Host "We did not find HttpRequestFilteringModule on ClientAccess ECP web.config" -ForegroundColor Red
                    }
                } else {
                    Write-Host "We did not find web.config for ClientAccess ECP" -ForegroundColor Red
                }
                Write-Host "Path: $($ExchangePath)ClientAccess\ecp\web.config"
            } else {
                Write-Host "We could not get FrontEnd or BackEnd Web.config path on $ExchangeServer." -ForegroundColor Red
            }
        } else {
            Write-Host "Cannot get Exchange installation path on $ExchangeServer" -ForegroundColor Red
        }

        $getSOs = $null
        $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
            ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
            ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
            ($_.Parameters -contains 'Enabled=False') -and
            ($null -ne $_.Server -and ($_.Server -contains $ExchangeServer)) }
        if ($getSOs) {
            $getSOs | Out-Host
            foreach ($so in $getSOs) {
                if ($so.Status -eq 'Accepted') {
                    Write-Host "AMSI is Disabled by $($so.Name) SettingOverride for $ExchangeServer" -ForegroundColor Yellow
                } else {
                    Write-Host "AMSI is Disabled by $($so.Name) SettingOverride for $ExchangeServer but it is not Accepted." -ForegroundColor Red
                }
            }
        } else {
            Write-Host $msgNewLine
            Write-Host "AMSI is Enabled on Server $ExchangeServer." -ForegroundColor Green
            Write-Host "We did not find any Settings Override that remove AMSI on server $ExchangeServer."
            Write-Host " "
        }
    }
}

process {

    $BuildVersion = ""

    Write-Host ("Test-AMSI.ps1 script version $($BuildVersion)") -ForegroundColor Green

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Test-AMSI-VersionsURL" -Confirm:$false) {
        ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/Test-AMSI-VersionsURL" -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
        return
    }

    if (-not (Confirm-Administrator)) {
        Write-Warning "This script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator and try again."
        exit
    }

    $exchangeShell = Confirm-ExchangeShell
    if (-not($exchangeShell.ShellLoaded)) {
        Write-Warning "Failed to load Exchange Management Shell..."
        exit
    }

    $localServer = $null
    $localServer = Get-ExchangeServer $env:COMPUTERNAME -ErrorAction SilentlyContinue
    if ($localServer -and $localServer.IsEdgeServer) {
        Write-Warning "This script cannot be executed in an Edge Server."
        exit
    }

    $bar = ""
    1..($Host.UI.RawUI.WindowSize.Width) | ForEach-Object { $bar += "-" }
    Write-Host " "
    Write-Host $bar

    $filterList = @()

    if ($PSCmdlet.ParameterSetName -eq "TestAMSI" -or $PSCmdlet.ParameterSetName -eq "TestAMSIAll") {
        $TestAMSI = $true
    }

    if ($null -eq $ServerList -and ($RestartIIS -or $CheckAMSIConfig -or $TestAMSI) -and (-not $AllServers)) {
        if (-not $localServer) {
            Write-Warning "This option is not available in a management tools server. You must select a server with any of the following parameters: ServerList, AllServers, Sites."
            exit
        }
        $ServerList = $env:COMPUTERNAME
    }

    Write-Host " "
    Write-Host "AMSI only support on Exchange 2016 CU21 or newer, Exchange 2019 CU10 or newer and running on Windows 2016 or newer" -ForegroundColor Green
    Write-Host " "

    $SupportedExchangeServers = New-Object 'System.Collections.Generic.List[object]'
    Get-ExchangeServer | Where-Object { $_.IsClientAccessServer } | ForEach-Object {
        $server = $_
        $versionInformation = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion.ToString()
        switch ($versionInformation.MajorVersion) {
            "Exchange2016" { if ($versionInformation.BuildVersion -ge "15.1.2308.8") { $SupportedExchangeServers.Add($server); break } }
            "Exchange2019" { if ($versionInformation.BuildVersion -ge "15.2.922.7") { $SupportedExchangeServers.Add($server); break } }
        }
    }

    $uniqueSites = $null
    if ($localServer) {
        $uniqueSites = $SupportedExchangeServers.Site.Name | Get-Unique
    } else {
        $uniqueSites = $SupportedExchangeServers.Site | Get-Unique | ForEach-Object { $_.split('/')[-1] }
    }
    $sitesCounter = $uniqueSites.count

    if ($Sites) {
        foreach ($site in $Sites) {
            if ($uniqueSites -notcontains $site) {
                Write-Warning "We did not find site $site"
            }
        }
        if ($localServer) {
            $fullList = ($SupportedExchangeServers | Where-Object { $Sites -contains $_.Site.Name } | Select-Object Name).Name
        } else {
            $fullList = ($SupportedExchangeServers | Where-Object { $Sites -contains $_.Site.split('/')[-1] } | Select-Object Name).Name
        }
    } else {
        $fullList = ($SupportedExchangeServers | Select-Object Name).Name
    }

    $Version = $null
    if ($AllServers) {
        foreach ($server in $fullList) {
            $serverName = $server.Split('.')[0]
            if ($SupportedExchangeServers.Name -contains $serverName) {
                if (HasWindowsVersionAmsiSupport -server $server) {
                    $filterList += $serverName
                }
            } else {
                Write-Warning "$server is not an Exchange version with AMSI support."
            }
        }
    } else {
        foreach ($server in $ServerList) {
            $serverName = $server.Split('.')[0]
            if ($fullList -contains $serverName) {
                if ($SupportedExchangeServers.Name -contains $serverName) {
                    if (HasWindowsVersionAmsiSupport -server $server) {
                        $filterList += $serverName
                    }
                } else {
                    Write-Warning "$server is not an Exchange version with AMSI support."
                }
            } else {
                Write-Warning "We did not find any Exchange server with name: $server"
                if ($TestAMSI) {
                    $filterList += $server
                }
            }
        }
    }

    if ((($filterList.count -gt 0) -or
            $TestAMSI -or
           (($EnableAMSI -or $DisableAMSI) -and
            -not $ServerList)) -and
        $SupportedExchangeServers.count -gt 0) {

        if ($TestAMSI) {
            foreach ($server in $filterList) {
                Write-Host $bar
                Write-Host " "
                Write-Host "Testing $($server):" -ForegroundColor Magenta
                CheckServerAMSI -Server $server
            }
            Write-Host " "
        }
        if ($CheckAMSIConfig) {
            if ($filterList) {
                foreach ($server in $filterList) {
                    Write-Host $bar
                    Write-Host " "
                    Write-Host "Checking $($server):" -ForegroundColor Magenta
                    Write-Host " "
                    CheckAMSIConfig -ExchangeServer $server
                    Write-Host " "
                }
            }
            Write-Host $bar
            Write-Host " "
            $getSOs = $null
            $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
                ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
                ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
                ($_.Parameters -contains 'Enabled=False') -and
                ($null -eq $_.Server) }
            if ($getSOs) {
                $getSOs | Out-Host
                foreach ($so in $getSOs) {
                    if ($so.Status -eq 'Accepted') {
                        Write-Warning "AMSI is Disabled by $($so.Name) SettingOverride at organization Level."
                    } else {
                        Write-Host "AMSI is Disabled by $($so.Name) SettingOverride at organization Level but it is not Accepted." -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "AMSI is Enabled for Exchange at Organization Level." -ForegroundColor Green
                Write-Host "We did not find any Settings Override that remove AMSI at organization Level."
                Write-Host " "
            }
        }

        $needsRefresh = 0
        if ($EnableAMSI) {
            if ($filterList) {
                foreach ($server in $filterList) {
                    Write-Host $bar
                    Write-Host " "
                    $getSOs = $null
                    $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
                        ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
                        ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
                        ($_.Parameters -contains 'Enabled=False') -and
                        ($null -ne $_.Server -and ($_.Server -contains $server)) }
                    if ($null -eq $getSOs) {
                        Write-Host "We did not find Get-SettingOverride that disabled AMSI on $server"
                        Write-Warning "AMSI is NOT disabled on $server"
                    } else {
                        foreach ($so in $getSOs) {
                            if ($so.Status -eq 'Accepted') {
                                Write-Warning "AMSI is Disabled by $($so.Name) SettingOverride on $server"
                            } else {
                                Write-Warning "AMSI is Disabled by $($so.Name) SettingOverride on $server but it is not Accepted."
                            }
                            $so | Out-Host
                            if (-not $WhatIfPreference) { Write-Host "Removing SettingOverride $($so.Name)" }
                            $rso = $null
                            Remove-SettingOverride -Identity $so.Name -Confirm:$false -WhatIf:$WhatIfPreference -ErrorVariable $rso
                            if (-not $WhatIfPreference) {
                                if ($rso) {
                                    Write-Host "We could not remove the SettingOverride on $server" -ForegroundColor Red
                                } else {
                                    Write-Host "Enabled on $server" -ForegroundColor Green
                                    Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                                    Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                                    $needsRefresh++
                                }
                            }
                        }
                    }
                }
            } else {
                Write-Host $bar
                Write-Host " "
                $getSOs = $null
                $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
                    ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
                    ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
                    ($_.Parameters -contains 'Enabled=False') -and
                    ($null -eq $_.Server) }
                if ($null -eq $getSOs) {
                    Write-Host "We did not find Get-SettingOverride that disabled AMSI at Organization level"
                    Write-Warning "AMSI is NOT disabled on Exchange configuration at organization level"
                } else {
                    foreach ($so in $getSOs) {
                        if ($so.Status -eq 'Accepted') {
                            Write-Warning "AMSI is Disabled by $($so.Name) SettingOverride at Organization level"
                        } else {
                            Write-Warning "AMSI is Disabled by $($so.Name) SettingOverride at Organization level but it is not Accepted."
                        }
                        $so | Out-Host
                        if (-not $WhatIfPreference) { Write-Host "Removing SettingOverride $($so.Name)" }
                        $rso = $null
                        Remove-SettingOverride -Identity $so.Name -Confirm:$false -WhatIf:$WhatIfPreference -ErrorVariable $rso
                        if (-not $WhatIfPreference) {
                            if ($rso) {
                                Write-Host "We could not remove the SettingOverride on $server" -ForegroundColor Red
                            } else {
                                Write-Host "Enabled AMSI at Organization Level" -ForegroundColor Green
                                foreach ($server in $SupportedExchangeServers) {
                                    Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                                    Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                                    $needsRefresh++
                                }
                            }
                        }
                    }
                }
            }
        }

        if ($DisableAMSI) {
            if ($filterList) {
                foreach ($server in $filterList) {
                    Write-Host $bar
                    Write-Host " "
                    $getSOs = $null
                    $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
                        ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
                        ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
                        ($_.Parameters -contains 'Enabled=False') -and
                        ($null -ne $_.Server -and ($_.Server -contains $server)) }
                    if ($null -eq $getSOs) {
                        if (-not $WhatIfPreference) {
                            Write-Warning "Disabling on $server by DisablingAMSIScan-$server SettingOverride"
                        }
                        $nso = $null
                        $nso = New-SettingOverride -Name "DisablingAMSIScan-$server" -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script" -Server $server -WhatIf:$WhatIfPreference
                        if (-not $WhatIfPreference) {
                            if ($nso) {
                                Write-Warning "Disabled on $server by DisablingAMSIScan-$server SettingOverride"
                                Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                                Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                                $needsRefresh++
                            } else {
                                Write-Host "Failed to disable AMSI on $server by DisablingAMSIScan-$server SettingOverride" -ForegroundColor Red
                            }
                        }
                    } else {
                        foreach ($so in $getSOs) {
                            if ($so.Status -eq 'Accepted') {
                                Write-Host "AMSI is already disabled on $server by $($so.Name) SettingOverride" -ForegroundColor Yellow
                            } else {
                                Write-Host "AMSI is already disabled on $server by $($so.Name) SettingOverride but it is not Accepted." -ForegroundColor Red
                            }
                        }
                    }
                }
            } else {
                Write-Host $bar
                Write-Host " "
                $getSOs = $null
                $getSOs = Get-SettingOverride -ErrorAction SilentlyContinue | Where-Object {
                    ($null -eq $_.Server) -and
                    ($_.ComponentName.Equals('Cafe', [System.StringComparison]::OrdinalIgnoreCase)) -and
                    ($_.SectionName.Equals('HttpRequestFiltering', [System.StringComparison]::OrdinalIgnoreCase)) -and
                    ($_.Parameters -contains 'Enabled=False') }
                if ($null -eq $getSOs) {
                    if (-not $WhatIfPreference) {
                        Write-Warning "Disabling AMSI at Organization Level by DisablingAMSIScan-OrgLevel SettingOverride"
                    }
                    $nso = $null
                    $nso = New-SettingOverride -Name DisablingAMSIScan-OrgLevel -Component Cafe -Section HttpRequestFiltering -Parameters ("Enabled=False") -Reason "Disabled via CSS-Exchange Script" -WhatIf:$WhatIfPreference
                    if (-not $WhatIfPreference) {
                        if ($nso) {
                            Write-Warning "Disabled AMSI at Organization Level by DisablingAMSIScan-OrgLevel SettingOverride"
                            foreach ($server in $SupportedExchangeServers) {
                                Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                                Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                                $needsRefresh++
                            }
                        } else {
                            Write-Host "Failed to disable AMSI at Organization Level by DisablingAMSIScan-OrgLevel SettingOverride" -ForegroundColor Red
                        }
                    }
                } else {
                    foreach ($so in $getSOs) {
                        if ($so.Status -eq 'Accepted') {
                            Write-Warning "AMSI is already disabled at Organization Level by $($so.Name) SettingOverride"
                        } else {
                            Write-Host "AMSI is already disabled at Organization Level by $($so.Name) SettingOverride but it is not Accepted." -ForegroundColor Red
                        }
                    }
                }
            }
        }

        if ($needsRefresh -gt 0) {
            Write-Host " "
            Write-Host $bar
            Write-Host " "
            if ($sitesCounter -gt 1) {
                Write-Warning "You have a multi site environment, confirm that all affected Exchange sites has replicated changes."
                Write-Host "You can push changes on your DCs with: repadmin /syncall /AdeP"
                Write-Host " "
            }
            Write-Warning "Remember to restart IIS to be effective on all affected servers."
            Write-Host "You can accomplish this by running .\Test-AMSI.ps1 -RestartIIS"
            Write-Host " "
        }

        if ($RestartIIS) {
            if ($filterList) {
                $yesToAll = $false
                $noToAll = $false

                foreach ($server in $filterList) {
                    if (-not $WhatIfPreference) {
                        Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh -Server $server | Out-Null
                        Write-Host "Refreshed Get-ExchangeDiagnosticInfo on $server"
                    }
                }

                if ($Force -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "This command wil restart the following IIS servers: $filterList", $true, [ref]$yesToAll, [ref]$noToAll)) {
                    foreach ($server in $filterList) {
                        Write-Host " "
                        if ($Force -or $filterList.Count -eq 1 -or $PSCmdlet.ShouldContinue("Are you sure you want to do it?", "You will restart IIS on server $server", $true, [ref]$yesToAll, [ref]$noToAll)) {
                            if ($server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
                                if (-not $WhatIfPreference) { Write-Host "Restarting local IIS on $server" }
                                Get-Service W3SVC, WAS | Restart-Service -Force -WhatIf:$WhatIfPreference
                            } else {
                                if (-not $WhatIfPreference) { Write-Host "Restarting Remote IIS on $server" }
                                Get-Service W3SVC, WAS -ComputerName $server | Restart-Service -Force -WhatIf:$WhatIfPreference
                            }
                            if (-not $WhatIfPreference) { Write-Host "Ended $server Restart" }
                        }
                    }
                }
            }
        }
    } else {
        Write-Warning "We did not find Exchange servers with AMSI support"
    }
    Write-Host $bar
    Write-Host " "
    Write-Host 'You can find additional information at:'
    Write-Host 'https://aka.ms/ExchangeAMSI' -ForegroundColor Cyan
    Write-Host " "
}
