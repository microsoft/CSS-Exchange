# Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.
#
# Examples
#
# Check the local Exchange server only and save the report:
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers and save the reports:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers, but only display the results, don't save them:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1


[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]
    $ComputerName = $env:COMPUTERNAME,

    [string]
    $OutPath
)

process {

    function Test-ExchangeProxyLogon {
        <#
	.SYNOPSIS
		Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

	.DESCRIPTION
		Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.
		Will do so in parallel if more than one server is specified, so long as names aren't provided by pipeline.

		The vulnerabilities are described in CVE-2021-26855, 26858, 26857, and 27065

	.PARAMETER ComputerName
		The list of server names to scan for signs of compromise.
		Do not provide these by pipeline if you want parallel processing.

	.PARAMETER Credential
		Credentials to use for remote connections.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon

		Scans the current computer for signs of ProxyLogon vulnerability compromise.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn

		Scans all exchange servers in the organization for ProxyLogon vulnerability compromises
#>
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]
            $ComputerName = $env:COMPUTERNAME,

            [pscredential]
            $Credential
        )
        begin {
            #region Remoting Scriptblock
            $scriptBlock = {
                #region Functions
                function Get-ExchangeInstallPath {
                    $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                    if ($null -eq $p) {
                        $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                    }

                    return $p
                }

                function Get-Cve26855 {
                    [CmdletBinding()]
                    param ()

                    Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs"

                    $exchangePath = Get-ExchangeInstallPath

                    $files = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy" -Filter '*.log').FullName
                    $count = 0
                    $allResults = @()
                    $sw = New-Object System.Diagnostics.Stopwatch
                    $sw.Start()
                    $files | ForEach-Object {
                        $count++

                        if ($sw.ElapsedMilliseconds -gt 500) {
                            Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs" -Status "$count / $($files.Count)" -PercentComplete ($count * 100 / $files.Count)
                            $sw.Restart()
                        }

                        if ((Get-ChildItem $_ -ErrorAction SilentlyContinue | Select-String "ServerInfo~").Count -gt 0) {
                            $fileResults = @(Import-Csv -Path $_ -ErrorAction SilentlyContinue | Where-Object AnchorMailbox -Like 'ServerInfo~*/*' | Select-Object -Property DateTime, RequestId, ClientIPAddress, UrlHost, UrlStem, RoutingHint, UserAgent, AnchorMailbox, HttpStatus)
                            $fileResults | ForEach-Object {
                                $allResults += $_
                            }
                        }
                    }

                    Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs" -Completed

                    return $allResults
                }

                function Get-Cve26857 {
                    [CmdletBinding()]
                    param ()

                    Get-WinEvent -FilterHashtable @{
                        LogName      = 'Application'
                        ProviderName = 'MSExchange Unified Messaging'
                        Level        = '2'
                    } -ErrorAction SilentlyContinue | Where-Object Message -Like "*System.InvalidCastException*"
                }

                function Get-Cve26858 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath

                    Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path
                }

                function Get-Cve27065 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Select-String "Set-.+VirtualDirectory" -List | Select-Object -ExpandProperty Path
                }

                function Get-SuspiciousFile {
                    [CmdletBinding()]
                    param ()

                    foreach ($file in Get-ChildItem -Recurse -Path "$env:WINDIR\temp\lsass.*dmp") {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'LsassDump'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                    foreach ($file in Get-ChildItem -Recurse -Path "c:\root\lsass.*dmp" -ErrorAction SilentlyContinue) {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'LsassDump'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                    foreach ($file in Get-ChildItem -Recurse -Path $env:ProgramData -ErrorAction SilentlyContinue | Where-Object Extension -Match ".7z$|.zip$|.rar$") {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'SuspiciousArchive'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                }

                function Get-OldestLog {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath

                    [PSCustomObject]@{
                        Oabgen           = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        Ecp              = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        AutodProxy       = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        EasProxy         = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        EcpProxy         = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        EwsProxy         = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        MapiProxy        = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        OabProxy         = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        OwaProxy         = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        OwaCalendarProxy = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        PowershellProxy  = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                        RpcHttpProxy     = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    }
                }
                #endregion Functions

                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Cve26855     = @(Get-Cve26855)
                    Cve26857     = @(Get-Cve26857)
                    Cve26858     = @(Get-Cve26858)
                    Cve27065     = @(Get-Cve27065)
                    Suspicious   = @(Get-SuspiciousFile)
                    OldestLogs   = Get-OldestLog
                }
            }
            #endregion Remoting Scriptblock
            $parameters = @{
                ScriptBlock = $scriptBlock
            }
            if ($Credential) { $parameters.Credential = $Credential }
        }
        process {
            Invoke-Command @parameters -ComputerName $ComputerName
        }
    }

    function Write-ProxyLogonReport {
        <#
	.SYNOPSIS
		Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

	.DESCRIPTION
		Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

	.PARAMETER InputObject
		The reports provided by Test-ExchangeProxyLogon

	.PARAMETER OutPath
		Path to a FOLDER in which to generate output logfiles.
		This command will only write to the console screen if no path is provided.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn | Write-ProxyLogonReport -OutPath C:\logs

		Gather data from all exchange servers in the organization and write a report to C:\logs
#>
        [CmdletBinding()]
        param (
            [parameter(ValueFromPipeline = $true)]
            $InputObject,

            [string]
            $OutPath
        )

        begin {
            if ($OutPath) {
                New-Item $OutPath -ItemType Directory -Force | Out-Null
            }
        }

        process {
            foreach ($report in $InputObject) {
                Write-Host "ProxyLogon Status: Exchange Server $($report.ComputerName)"
                if (-not ($report.Cve26855.Count -or $report.Cve26857.Count -or $report.Cve26858.Count -or $report.Cve27065.Count -or $report.Suspicious.Count)) {
                    Write-Host "  Nothing suspicious detected" -ForegroundColor Green
                    Write-Host ""
                    continue
                }

                if ($report.Cve26855.Count -gt 0) {
                    Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
                    if ($OutPath) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
                        $report.Cve26855 | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve26855 | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    Write-Host ""
                }
                if ($report.Cve26857.Count -gt 0) {
                    Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
                    Write-Host "  $(@($report.Cve26857).Count) events found"
                    if ($OutPath) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
                        $report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve26858.Count -gt 0) {
                    Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Download failed and temporary file' entries:"
                    foreach ($entry in $report.Cve26858) {
                        Write-Host "   $entry"
                    }
                    if ($OutPath) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
                        $report.Cve26858 | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] Suspicious activity found in ECP logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Set-*VirtualDirectory' entries:"
                    foreach ($entry in $report.Cve27065) {
                        Write-Host "   $entry"
                    }
                    if ($OutPath) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065.log"
                        $report.Cve27065 | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Suspicious.Count -gt 0) {
                    Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
                    if ($OutPath) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
                        $report.Suspicious | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        foreach ($entry in $report.Suspicious) {
                            Write-Host "   $($entry.Type) : $($entry.Path)"
                        }
                    }
                }

                Write-Host "Oldest log files:"
                $report.OldestLogs | Format-Table | Out-Host
                if ($OutPath) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-OldestLogs.csv"
                    $report.OldestLogs | Export-Csv -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                }
            }
        }
    }

    $ComputerName | Test-ExchangeProxyLogon | Write-ProxyLogonReport -OutPath $OutPath
}
