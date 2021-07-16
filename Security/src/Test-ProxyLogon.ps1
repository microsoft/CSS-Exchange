# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.
#
# Examples
#
# Check the local Exchange server only and save the report:
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check the local Exchange server, copy the files and folders to the outpath\<ComputerName>\ path
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs -CollectFiles
#
# Check all Exchange servers and save the reports:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers, but only display the results, don't save them:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -DisplayOnly
#
#Requires -Version 3

[CmdletBinding(DefaultParameterSetName = "AsScript")]
param (
    [Parameter(ParameterSetName = "AsScript", ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Fqdn')]
    [string[]]
    $ComputerName,

    [Parameter(ParameterSetName = "AsScript")]
    [string]
    $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

    [Parameter(ParameterSetName = "AsScript")]
    [switch]
    $DisplayOnly,

    [Parameter(ParameterSetName = "AsScript")]
    [switch]
    $CollectFiles,

    [Parameter(ParameterSetName = 'AsModule')]
    [switch]
    $Export,

    [Parameter(ParameterSetName = "AsScript")]
    [System.Management.Automation.PSCredential]
    $Credential
)
begin {
    #region Functions
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
            $ComputerName,

            [System.Management.Automation.PSCredential]
            $Credential
        )
        begin {
            #region Remoting Scriptblock
            $scriptBlock = {
                #region Functions
                function Get-ExchangeInstallPath {
                    return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                }

                function Get-Cve26855 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26855 test."
                        return
                    }

                    $HttpProxyPath = Join-Path -Path $exchangePath -ChildPath "Logging\HttpProxy"
                    $Activity = "Checking for CVE-2021-26855 in the HttpProxy logs"

                    $outProps = @(
                        "DateTime", "RequestId", "ClientIPAddress", "UrlHost",
                        "UrlStem", "RoutingHint", "UserAgent", "AnchorMailbox",
                        "HttpStatus"
                    )

                    $files = [System.Array](Get-ChildItem -Recurse -Path $HttpProxyPath -Filter '*.log').FullName

                    $allResults = @{
                        Hits     = [System.Collections.ArrayList]@()
                        FileList = [System.Collections.ArrayList]@()
                    }

                    $progressId = [Math]::Abs(($env:COMPUTERNAME).GetHashCode())

                    Write-Progress -Activity $Activity -Id $progressId

                    $sw = New-Object System.Diagnostics.Stopwatch
                    $sw.Start()

                    For ( $i = 0; $i -lt $files.Count; ++$i ) {
                        if ($sw.ElapsedMilliseconds -gt 1000) {
                            Write-Progress -Activity $Activity -Status "$i / $($files.Count)" -PercentComplete ($i * 100 / $files.Count) -Id $progressId
                            $sw.Restart()
                        }

                        if ( ( Test-Path $files[$i] ) -and ( Select-String -Path $files[$i] -Pattern "ServerInfo~" -Quiet ) ) {
                            [Void]$allResults.FileList.Add( $files[$i] )

                            Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue |
                                Where-Object { $_.AnchorMailbox -Like 'ServerInfo~*/*' -and $_.AnchorMailbox -notlike 'ServerInfo~*/autodiscover*' -and $_.AnchorMailbox -notlike 'ServerInfo~localhost*/*' } |
                                Select-Object -Property $outProps |
                                ForEach-Object {
                                    [Void]$allResults.Hits.Add( $_ )
                                }
                        }
                    }

                    Write-Progress -Activity $Activity -Id $progressId -Completed

                    return $allResults
                }

                function Get-Cve26857 {
                    [CmdletBinding()]
                    param ()
                    try {
                        Get-WinEvent -FilterHashtable @{
                            LogName      = 'Application'
                            ProviderName = 'MSExchange Unified Messaging'
                            Level        = '2'
                        } -ErrorAction SilentlyContinue | Where-Object Message -Like "*System.InvalidCastException*"
                    } catch {
                        Write-Host "  MSExchange Unified Messaging provider is not present or events not found in the Application Event log"
                    }
                }

                function Get-Cve26858 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26858 test."
                        return
                    }

                    $allResults = @{
                        downloadPaths = [System.Collections.ArrayList]@()
                        filePaths     = [System.Collections.ArrayList]@()
                    }

                    $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path)

                    for ( $i = 0; $i -lt $files.Count; $i++) {
                        $maliciousPathFound = $false
                        $loginstance = Select-String -Path $files[$i] -Pattern "Download failed and temporary file"
                        foreach ($logLine in $loginstance) {
                            $path = ([String]$logLine | Select-String -Pattern 'Download failed and temporary file (.*?) needs to be removed').Matches.Groups[1].value
                            if ($null -ne $path -and (-not ($path.StartsWith("'$exchangePath" + "ClientAccess\OAB", "CurrentCultureIgnoreCase")))) {
                                [Void]$allResults.downloadPaths.Add( [String]$path )
                                $maliciousPathFound = $true
                            }
                        }
                        if ($maliciousPathFound) {
                            $allResults.FilePaths.Add([String]$files[$i])
                        }
                    }
                    return $allResults
                }

                function Get-Cve27065 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath

                    $outProps = @(
                        "DateTime", "RequestId", "ClientIPAddress", "UrlHost",
                        "UrlStem", "RoutingHint", "UserAgent", "AnchorMailbox",
                        "HttpStatus"
                    )

                    $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -Filter '*.log').FullName
                    $allResults = @{
                        resetVDirHits           = [System.Collections.ArrayList]@()
                        resetVDirFiles          = [System.Collections.ArrayList]@()
                        setVDirMaliciousUrlLogs = [System.Collections.ArrayList]@()
                    }
                    For ( $i = 0; $i -lt $files.Count; ++$i ) {

                        if ((Get-ChildItem $files[$i] -ErrorAction SilentlyContinue | Select-String -Pattern "ServerInfo~").Count -gt 0) {

                            $hits = @(Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue | Where-Object { $_.AnchorMailbox -Like 'ServerInfo~*/*Reset*VirtualDirectory#' -and $_.HttpStatus -eq 200 } |
                                    Select-Object -Property $outProps)
                            if ($hits.Count -gt 0) {
                                $hits | ForEach-Object {
                                    [Void]$allResults.resetVDirHits.Add( $_ )
                                }
                                [Void]$allResults.resetVDirFiles.Add( $files[$i] )
                            }
                        }
                    }
                    $allResults.setVDirMaliciousUrlLogs = Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Select-String "Set-.+VirtualDirectory.+?(?=Url).+<\w+.*>(.*?)<\/\w+>.+?(?=VirtualDirectory)" -List | Select-Object -ExpandProperty Path
                    return $allResults
                }

                function Get-SuspiciousFile {
                    [CmdletBinding()]
                    param ()

                    $zipFilter = ".7z", ".zip", ".rar"
                    $dmpFilter = "lsass.*dmp"
                    $dmpPaths = "c:\root", "$env:WINDIR\temp"

                    Get-ChildItem -Path $dmpPaths -Filter $dmpFilter -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            [PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                Type         = 'LsassDump'
                                Path         = $_.FullName
                                Name         = $_.Name
                                LastWrite    = $_.LastWriteTimeUtc
                            }
                        }

                    Get-ChildItem -Path $env:ProgramData -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            If ( $_.Extension -in $zipFilter ) {
                                [PSCustomObject]@{
                                    ComputerName = $env:COMPUTERNAME
                                    Type         = 'SuspiciousArchive'
                                    Path         = $_.FullName
                                    Name         = $_.Name
                                    LastWrite    = $_.LastWriteTimeUtc
                                }
                            }
                        }
                }

                function Get-AgeInDays {
                    param ( $dateString )
                    if ( $dateString -and $dateString -as [DateTime] ) {
                        $CURTIME = Get-Date
                        $age = $CURTIME.Subtract($dateString)
                        return $age.TotalDays.ToString("N1")
                    }
                    return ""
                }

                function Get-LogAge {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping log age checks."
                        return $null
                    }

                    [PSCustomObject]@{
                        Oabgen           = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        Ecp              = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        AutodProxy       = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EasProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EcpProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EwsProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        MapiProxy        = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OabProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaCalendarProxy = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        PowershellProxy  = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        RpcHttpProxy     = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    }
                }
                #endregion Functions

                $results = [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Cve26855     = Get-Cve26855
                    Cve26857     = @(Get-Cve26857)
                    Cve26858     = Get-Cve26858
                    Cve27065     = Get-Cve27065
                    LogAgeDays   = Get-LogAge
                    IssuesFound  = $false
                    Suspicious   = $null
                }

                if ($results.Cve26855.Hits.Count -or $results.Cve26857.Count -or $results.Cve26858.downloadPaths.Count -or $results.Cve27065.resetVDirHits.Count -or $results.Cve27065.setVDirMaliciousUrlLogs.Count) {
                    $results.Suspicious = @(Get-SuspiciousFile)
                    $results.IssuesFound = $true
                }

                $results
            }
            #endregion Remoting Scriptblock
            $parameters = @{
                ScriptBlock = $scriptBlock
            }
            if ($Credential) { $parameters['Credential'] = $Credential }
        }
        process {
            if ($null -ne $ComputerName) {
                Invoke-Command @parameters -ComputerName $ComputerName
            } else {
                Invoke-Command @parameters
            }
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
            $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

            [switch]
            $DisplayOnly,

            [switch]
            $CollectFiles
        )

        begin {
            if ($OutPath -and -not $DisplayOnly) {
                New-Item $OutPath -ItemType Directory -Force | Out-Null
            }
        }

        process {
            foreach ($report in $InputObject) {

                $isLocalMachine = $report.ComputerName -eq $env:COMPUTERNAME

                if ($CollectFiles) {
                    $LogFileOutPath = $OutPath + "\CollectedLogFiles\" + $report.ComputerName
                    if (-not (Test-Path -Path $LogFileOutPath)) {
                        New-Item $LogFileOutPath -ItemType Directory -Force | Out-Null
                    }
                }

                Write-Host "ProxyLogon Status: Exchange Server $($report.ComputerName)"

                if ($null -ne $report.LogAgeDays) {
                    Write-Host ("  Log age days: Oabgen {0} Ecp {1} Autod {2} Eas {3} EcpProxy {4} Ews {5} Mapi {6} Oab {7} Owa {8} OwaCal {9} Powershell {10} RpcHttp {11}" -f `
                            $report.LogAgeDays.Oabgen, `
                            $report.LogAgeDays.Ecp, `
                            $report.LogAgeDays.AutodProxy, `
                            $report.LogAgeDays.EasProxy, `
                            $report.LogAgeDays.EcpProxy, `
                            $report.LogAgeDays.EwsProxy, `
                            $report.LogAgeDays.MapiProxy, `
                            $report.LogAgeDays.OabProxy, `
                            $report.LogAgeDays.OwaProxy, `
                            $report.LogAgeDays.OwaCalendarProxy, `
                            $report.LogAgeDays.PowershellProxy, `
                            $report.LogAgeDays.RpcHttpProxy)

                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-LogAgeDays.csv"
                        $report.LogAgeDays | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                }

                if (-not $report.IssuesFound) {
                    Write-Host "  Nothing suspicious detected" -ForegroundColor Green
                    Write-Host ""
                    continue
                }
                if ($report.Cve26855.Hits.Count -gt 0) {
                    Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
                        $report.Cve26855.Hits | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve26855.Hits | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26855")) {
                            Write-Host " Creating CVE26855 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26855" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve26855.FileList) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26855" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26855"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Cve26857.Count -gt 0) {
                    Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
                    Write-Host "  $(@($report.Cve26857).Count) events found"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
                        $report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }

                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host "`n`r Copying Application Event Log"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26857")) {
                            Write-Host "  Creating CVE26857 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26857" -ItemType Directory -Force | Out-Null
                        }

                        Start-Process wevtutil -ArgumentList "epl Software $($LogFileOutPath)\CVE26857\Application.evtx"
                    }
                    Write-Host ""
                }
                if ($report.Cve26858.downloadPaths.Count -gt 0) {
                    Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
                    Write-Host "  Webshells possibly downloaded in file system. Explore below locations:" -ForegroundColor Red
                    if (-not $DisplayOnly) {
                        $newFileDownloadPaths = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858-DownloadPaths.log"
                        $newFileForFilePaths = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
                        $report.Cve26858.downloadPaths | Set-Content -Path $newFileDownloadPaths
                        $report.Cve26858.filePaths | Set-Content -Path $newFileForFilePaths
                        Write-Host "  Report exported to: $newFileForFilePaths"
                        Write-Host "  Report exported to: $newFileDownloadPaths"
                    } else {
                        $report.Cve26858.downloadPaths | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26858")) {
                            Write-Host " Creating CVE26858 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE26858" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve26858.filePaths) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26858" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26858"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.setVDirMaliciousUrlLogs.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] Suspicious activity found in ECP logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Set-*VirtualDirectory' entries (potentially malicious urls used):"
                    foreach ($entry in $report.Cve27065.setVDirMaliciousUrlLogs) {
                        Write-Host "   $entry"
                        if ($CollectFiles -and $isLocalMachine) {
                            Write-Host " Copying Files:"
                            if (-not (Test-Path -Path "$($LogFileOutPath)\CVE27065")) {
                                Write-Host " Creating CVE27065 Collection Directory"
                                New-Item "$($LogFileOutPath)\CVE27065" -ItemType Directory -Force | Out-Null
                            }
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE27065" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE27065"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065.log"
                        $report.Cve27065.setVDirMaliciousUrlLogs | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.resetVDirHits.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] Webshell possibly downloaded in file system" -ForegroundColor Red
                    Write-Host "  Please scan your file system for any malicious webshells. Reset-VirtualDirectory entries:"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065-ResetVDir.csv"
                        $report.Cve27065.resetVDirHits | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve27065.resetVDirHits | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\Cve27065")) {
                            Write-Host " Creating Cve27065 Collection Directory"
                            New-Item "$($LogFileOutPath)\Cve27065" -ItemType Directory -Force | Out-Null
                        }
                        foreach ($entry in $report.Cve27065.resetVDirFiles) {
                            if (Test-Path -Path $entry) {
                                Write-Host "  Copying $($entry) to $($LogFileOutPath)\Cve27065" -ForegroundColor Green
                                Copy-Item -Path $entry -Destination "$($LogFileOutPath)\Cve27065"
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                    Write-Host ""
                }
                if ($report.Suspicious.Count -gt 0) {
                    Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
                        $report.Suspicious | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        foreach ($entry in $report.Suspicious) {
                            Write-Host "   $($entry.Type) : $($entry.Path)"
                        }
                    }
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"

                        #Deleting and recreating suspiciousFiles folder to prevent overwrite exceptions due to folders (folder name: myfolder.zip)
                        if ( Test-Path -Path "$($LogFileOutPath)\SuspiciousFiles" ) {
                            Remove-Item -Path "$($LogFileOutPath)\SuspiciousFiles" -Recurse -Force
                        }
                        Write-Host "  Creating SuspiciousFiles Collection Directory"
                        New-Item "$($LogFileOutPath)\SuspiciousFiles" -ItemType Directory -Force | Out-Null

                        $fileNumber = 0
                        foreach ($entry in $report.Suspicious) {
                            if (Test-Path -Path $entry.path) {
                                Write-Host "  Copying $($entry.Path) to $($LogFileOutPath)\SuspiciousFiles" -ForegroundColor Green
                                Copy-Item -Path $entry.Path -Destination "$($LogFileOutPath)\SuspiciousFiles\$($entry.Name)_$fileNumber"
                                $fileNumber += 1
                            } else {
                                Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                            }
                        }
                    }
                }
            }
        }
    }
    #endregion Functions

    $paramTest = @{ }
    if ($Credential) { $paramTest['Credential'] = $Credential }
    $paramWrite = @{
        OutPath = $OutPath
    }
    if ($CollectFiles) { $paramWrite['CollectFiles'] = $true }
    if ($DisplayOnly) {
        $paramWrite = @{ DisplayOnly = $true }
    }

    $computerTargets = New-Object System.Collections.ArrayList
}
process {

    if ($Export) {
        Set-Item function:global:Test-ExchangeProxyLogon (Get-Command Test-ExchangeProxyLogon)
        Set-Item function:global:Write-ProxyLogonReport (Get-Command Write-ProxyLogonReport)
        return
    }

    # Gather up computer targets as they are piped into the command.
    # Passing them to Test-ExchangeProxyLogon in one batch ensures parallel processing
    foreach ($computer in $ComputerName) {
        $null = $computerTargets.Add($computer)
    }
}
end {
    if ($Export) { return }

    if ($computerTargets.Length -lt 1) {
        Test-ExchangeProxyLogon @paramTest | Write-ProxyLogonReport @paramWrite
    } else {
        Test-ExchangeProxyLogon -ComputerName $computerTargets.ToArray() @paramTest | Write-ProxyLogonReport @paramWrite
    }
}
