﻿<#
    .SYNOPSIS
        This script contains mitigations to help address the following vulnerabilities.
            CVE-2021-26855

        For more information on each mitigation please visit https://aka.ms/exchangevulns
        Use of the Exchange On-premises Mitigation Tool and the Microsoft Saftey Scanner are subject to the terms of the Microsoft Privacy Statement: https://aka.ms/privacy

	.DESCRIPTION
       This script has three operations it performs:
            Mitigation of CVE-2021-26855 via a URL Rewrite configuration. Note: this mitigates current known attacks.
            Malware scan of the Exchange Server via the Microsoft Safety Scanner
            Attempt to reverse any changes made by identified threats.

	.PARAMETER RunFullScan
        If true will determine if the server is vulnerable and run MSERT in full scan mode.

    .PARAMETER RollbackMitigation
        If true will only reverse the mitigations if present.

    .PARAMETER DoNotRunMSERT
        If true will not run MSERT.

    .PARAMETER DoNotRunMitigation
        If true will not apply mitigations.

	.EXAMPLE
		PS C:\> EOMT.ps1

		This will run the default mode which does the following:
            1. Checks if your server is vulnerable based on the presence of the SU patch or Exchange version
            2. Downloads and installs the IIS URL rewrite tool.
            3. Applies the URL rewrite mitigation (only if vulnerable).
            4. Runs the Microsoft Safety Scanner in "Quick Scan" mode.

	.EXAMPLE
		PS C:\> EOMT.ps1 -RollbackMitigation

        This will only rollback the URL rewrite mitigation.

	.EXAMPLE
        PS C:\> EOMT.ps1 -RunFullScan -DoNotRunMitigation

        This will only run the Microsoft Safety Scanner in "Full Scan" mode. We only recommend this option only if the initial quick scan discovered threats. The full scan may take hours or days to complete.

    .Link
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download
        https://aka.ms/privacy
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Invalid rule result')]
[Cmdletbinding()]
param (
    [switch]$RunFullScan,
    [switch]$RollbackMitigation,
    [switch]$DoNotRunMSERT,
    [switch]$DoNotRunMitigation
)

$ProgressPreference = "SilentlyContinue"
$EOMTDir = Join-Path $env:TEMP "msert"
$EOMTLogFile = Join-Path $EOMTDir "EOMT.log"
$msertLogPath = "$env:SystemRoot\debug\msert.log"
$msertLogArchivePath = "$env:SystemRoot\debug\msert.old.log"
$detectionFollowUpURL = 'https://go.microsoft.com/fwlink/?linkid=2157359'
$SummaryFile = "$env:SystemDrive\EOMTSummary.txt"

# Force TLS1.2 to make sure we can download from HTTPS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Run-Mitigate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [string]$WebSiteName = "Default Web Site",
        [string]$Stage = "MitigationProcess",
        [switch]$RollbackMitigation

    )

    function GetMsiProductVersion {
        param (
            [string]$filename
        )

        try {
            $windowsInstaller = New-Object -com WindowsInstaller.Installer

            $database = $windowsInstaller.GetType().InvokeMember(
                "OpenDatabase", "InvokeMethod", $Null,
                $windowsInstaller, @($filename, 0)
            )

            $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"

            $View = $database.GetType().InvokeMember(
                "OpenView", "InvokeMethod", $Null, $database, ($q)
            )

            try {
                $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) | Out-Null

                $record = $View.GetType().InvokeMember(
                    "Fetch", "InvokeMethod", $Null, $View, $Null
                )

                $productVersion = $record.GetType().InvokeMember(
                    "StringData", "GetProperty", $Null, $record, 1
                )

                return $productVersion
            } finally {
                if ($View) {
                    $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null) | Out-Null
                }
            }
        } catch {
            throw "Failed to get MSI file version the error was: {0}." -f $_
        }
    }

    function Get-InstalledSoftwareVersion {
        param (
            [ValidateNotNullOrEmpty()]
            [string[]]$Name
        )

        try {
            $UninstallKeys = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

            $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            }

            foreach ($UninstallKey in $UninstallKeys) {
                $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue
                foreach ($n in $Name) {
                    $SwKeys = $SwKeys | Where-Object { $_.GetValue('DisplayName') -like "$n" }
                }
                if ($SwKeys) {
                    foreach ($SwKey in $SwKeys) {
                        if ($SwKey.GetValueNames().Contains("DisplayVersion")) {
                            return $SwKey.GetValue("DisplayVersion")
                        }
                    }
                }
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }

    function Test-IIS10 {
        $iisRegPath = "hklm:\SOFTWARE\Microsoft\InetStp"

        if (Test-Path $iisRegPath) {
            $properties = Get-ItemProperty $iisRegPath
            if ($properties.MajorVersion -eq 10) {
                return $true
            }
        }

        return $false
    }

    function GetURLRewriteLink {
        $DownloadLinks = @{
            "v2.1" = @{
                "x86" = @{
                    "de-DE" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_de-DE.msi"
                    "en-US" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_en-US.msi"
                    "es-ES" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_es-ES.msi"
                    "fr-FR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_fr-FR.msi"
                    "it-IT" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_it-IT.msi"
                    "ja-JP" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ja-JP.msi"
                    "ko-KR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ko-KR.msi"
                    "ru-RU" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ru-RU.msi"
                    "zh-CN" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-CN.msi"
                    "zh-TW" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-TW.msi"
                }

                "x64" = @{
                    "de-DE" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_de-DE.msi"
                    "en-US" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
                    "es-ES" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_es-ES.msi"
                    "fr-FR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_fr-FR.msi"
                    "it-IT" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_it-IT.msi"
                    "ja-JP" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ja-JP.msi"
                    "ko-KR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ko-KR.msi"
                    "ru-RU" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ru-RU.msi"
                    "zh-CN" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-CN.msi"
                    "zh-TW" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-TW.msi"
                }
            }
            "v2.0" = @{
                "x86" = @{
                    "de-DE" = "https://download.microsoft.com/download/0/5/0/05045383-D280-4DC6-AE8C-81764118B0F9/rewrite_x86_de-DE.msi"
                    "en-US" = "https://download.microsoft.com/download/6/9/C/69C1195A-123E-4BE8-8EDF-371CDCA4EC6C/rewrite_2.0_rtw_x86.msi"
                    "es-ES" = "https://download.microsoft.com/download/1/D/9/1D9464B8-9F3B-4A86-97F2-AEC2AB48F481/rewrite_x86_es-ES.msi"
                    "fr-FR" = "https://download.microsoft.com/download/1/2/9/129A2686-9654-4B2A-82ED-FC7BCE2BCE93/rewrite_x86_fr-FR.msi"
                    "it-IT" = "https://download.microsoft.com/download/2/4/A/24AE553F-CA8F-43B3-ACF8-DAC526FC84F2/rewrite_x86_it-IT.msi"
                    "ja-JP" = "https://download.microsoft.com/download/A/6/9/A69D23A5-7CE3-4F80-B5AE-CF6478A5DE19/rewrite_x86_ja-JP.msi"
                    "ko-KR" = "https://download.microsoft.com/download/2/6/F/26FCA84A-48BC-4AEE-BD6A-B28ED595832E/rewrite_x86_ko-KR.msi"
                    "ru-RU" = "https://download.microsoft.com/download/B/1/F/B1FDE19F-B4F9-4EBF-9E50-5C9CDF0302D2/rewrite_x86_ru-RU.msi"
                    "zh-CN" = "https://download.microsoft.com/download/4/9/C/49CD28DB-4AA6-4A51-9437-AA001221F606/rewrite_x86_zh-CN.msi"
                    "zh-TW" = "https://download.microsoft.com/download/1/9/4/1947187A-8D73-4C3E-B62C-DC6C7E1B353C/rewrite_x86_zh-TW.msi"
                }
                "x64" = @{
                    "de-DE" = "https://download.microsoft.com/download/3/1/C/31CE0BF6-31D7-415D-A70A-46A430DE731F/rewrite_x64_de-DE.msi"
                    "en-US" = "https://download.microsoft.com/download/6/7/D/67D80164-7DD0-48AF-86E3-DE7A182D6815/rewrite_2.0_rtw_x64.msi"
                    "es-ES" = "https://download.microsoft.com/download/9/5/5/955337F6-5A11-417E-A95A-E45EE8C7E7AC/rewrite_x64_es-ES.msi"
                    "fr-FR" = "https://download.microsoft.com/download/3/D/3/3D359CD6-147B-42E9-BD5B-407D3A1F0B97/rewrite_x64_fr-FR.msi"
                    "it-IT" = "https://download.microsoft.com/download/6/8/B/68B8EFA8-9404-45A3-A51B-53D940D5E742/rewrite_x64_it-IT.msi"
                    "ja-JP" = "https://download.microsoft.com/download/3/7/5/375C965C-9D98-438A-8F11-7F417D071DC9/rewrite_x64_ja-JP.msi"
                    "ko-KR" = "https://download.microsoft.com/download/2/A/7/2A746C73-467A-4BC6-B5CF-C4E88BB40406/rewrite_x64_ko-KR.msi"
                    "ru-RU" = "https://download.microsoft.com/download/7/4/E/74E569F7-44B9-4D3F-BCA7-87C5FE36BD62/rewrite_x64_ru-RU.msi"
                    "zh-CN" = "https://download.microsoft.com/download/4/E/7/4E7ECE9A-DF55-4F90-A354-B497072BDE0A/rewrite_x64_zh-CN.msi"
                    "zh-TW" = "https://download.microsoft.com/download/8/2/C/82CE350D-2068-4DAC-99D5-AEB2241DB545/rewrite_x64_zh-TW.msi"
                }
            }
        }

        if (Test-IIS10) {
            $Version = "v2.1"
        } else {
            $Version = "v2.0"
        }

        if ([Environment]::Is64BitOperatingSystem) {
            $Architecture = "x64"
        } else {
            $Architecture = "x86"
        }

        if ((Get-Culture).Name -in @("de-DE", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "ko-KR", "ru-RU", "zn-CN", "zn-TW")) {
            $Language = (Get-Culture).Name
        } else {
            $Language = "en-US"
        }

        return $DownloadLinks[$Version][$Architecture][$Language]
    }

    #Configure Rewrite Rule consts
    $HttpCookieInput = '{HTTP_COOKIE}'
    $root = 'system.webServer/rewrite/rules'
    $inbound = '.*'
    $name = 'X-AnonResource-Backend Abort - inbound'
    $name2 = 'X-BEResource Abort - inbound'
    $pattern = '(.*)X-AnonResource-Backend(.*)'
    $pattern2 = '(.*)X-BEResource=(.+)/(.+)~(.+)'
    $filter = "{0}/rule[@name='{1}']" -f $root, $name
    $filter2 = "{0}/rule[@name='{1}']" -f $root, $name2

    Import-Module WebAdministration

    if ($RollbackMitigation) {
        $Message = "Starting rollback of mitigation on $env:computername"
        $RegMessage = "Starting rollback of mitigation"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $site = "IIS:\Sites\$WebSiteName"

        $mitigationFound = $false
        foreach ($f in @($filter, $filter2)) {
            if (Get-WebConfiguration -Filter $f -PSPath $site) {
                $mitigationFound = $true
                Clear-WebConfiguration -Filter $f -PSPath $site
            }
        }

        if ($mitigationFound) {
            $Rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' -Recurse
            if ($null -eq $Rules) {
                Clear-WebConfiguration -PSPath $site -Filter 'system.webServer/rewrite/rules'
            }

            $Message = "Rollback of mitigation complete on $env:computername"
            $RegMessage = "Rollback of mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $Message = "Mitigation not present on $env:computername"
            $RegMessage = "Mitigation not present"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        }
    } else {
        $Message = "Starting mitigation process on $env:computername"
        $RegMessage = "Starting mitigation process"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        #If IIS 10 check for URL rewrite 2.1 else URL rewrite 2.0
        $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

        #Install module
        if ($RewriteModule) {

            #Throwing an exception if incorrect rewrite module version is installed
            if (Test-IIS10) {
                if ($RewriteModule -eq "7.2.2") {
                    $Message = "Incorrect IIS URL Rewrite Module previously installed on $env:computername"
                    $RegMessage = "Incorrect IIS URL Rewrite Module previously installed"
                    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                    throw
                }
            } else {
                if ($RewriteModule -eq "7.2.1993") {
                    $Message = "Incorrect IIS URL Rewrite Module previously installed on $env:computername"
                    $RegMessage = "Incorrect IIS URL Rewrite Module previously installed"
                    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                    throw
                }
            }

            $Message = "IIS URL Rewrite Module is already installed on $env:computername"
            $RegMessage = "IIS URL Rewrite Module already installed"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $DownloadLink = GetURLRewriteLink
            $DownloadPath = Join-Path $EOMTDir "\$($DownloadLink.Split("/")[-1])"
            $RewriteModuleInstallLog = Join-Path $EOMTDir "\RewriteModuleInstall.log"

            $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
            [IO.File]::WriteAllBytes($DownloadPath, $response.Content)

            $MSIProductVersion = GetMsiProductVersion -filename $DownloadPath

            #If IIS 10 assert URL rewrite 2.1 else URL rewrite 2.0
            if (Test-IIS10) {
                if ($MSIProductVersion -eq "7.2.2") {
                    $Message = "Incorrect IIS URL Rewrite Module downloaded on $env:computername"
                    $RegMessage = "Incorrect IIS URL Rewrite Module downloaded"
                    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                    throw
                }
            } else {
                if ($MSIProductVersion -eq "7.2.1993") {
                    $Message = "Incorrect IIS URL Rewrite Module downloaded on $env:computername"
                    $RegMessage = "Incorrect IIS URL Rewrite Module downloaded"
                    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                    throw
                }
            }

            $Message = "Installing the IIS URL Rewrite Module on $env:computername"
            $RegMessage = "Installing IIS URL Rewrite Module"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

            $arguments = "/i `"$DownloadPath`" /quiet /log `"$RewriteModuleInstallLog`""
            $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"
            Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
            Start-Sleep -Seconds 15
            $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

            if ($RewriteModule) {
                $Message = "IIS URL Rewrite Module installed on $env:computername"
                $RegMessage = "IIS URL Rewrite Module installed"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
            } else {
                $Message = "Issue installing IIS URL Rewrite Module $env:computername"
                $RegMessage = "Issue installing IIS URL Rewrite Module"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
        }

        $Message = "Applying URL Rewrite configuration to $env:COMPUTERNAME :: $WebSiteName"
        $RegMessage = "Applying URL Rewrite configuration"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $site = "IIS:\Sites\$WebSiteName"

        try {
            if ((Get-WebConfiguration -Filter $filter -PSPath $site).name -eq $name) {
                Clear-WebConfiguration -Filter $filter -PSPath $site
            }

            if ((Get-WebConfiguration -Filter $filter2 -PSPath $site).name -eq $name2) {
                Clear-WebConfiguration -Filter $filter2 -PSPath $site
            }

            Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name; patternSyntax = 'Regular Expressions'; stopProcessing = 'False' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value $inbound
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input = $HttpCookieInput; matchType = '0'; pattern = $pattern; ignoreCase = 'True'; negate = 'False' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'type' -value 'AbortRequest'

            Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name2; patternSyntax = 'Regular Expressions'; stopProcessing = 'True' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter2/match" -name 'url' -value $inbound
            Set-WebConfigurationProperty -PSPath $site -filter "$filter2/conditions" -name '.' -value @{input = $HttpCookieInput; matchType = '0'; pattern = $pattern2; ignoreCase = 'True'; negate = 'False' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter2/action" -name 'type' -value 'AbortRequest'

            $Message = "Mitigation complete on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } catch {
            $Message = "Mitigation failed on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation failed"
            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }
    }
}

function Run-MSERT {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [switch] $RunFullScan
    )
    $Stage = "MSERTProcess"
    if ($DoNotRunMSERT) {
        $Message = "Skipping mitigation -DoNotRunMSERT set on $env:computername"
        $RegMessage = "Skipping mitigation -DoNotRunMSERT"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        return
    }

    #Check for KB4474419
    $OS = [System.Environment]::OSVersion
    if ($OS.Version.Major -eq 6 -and $OS.Version.Minor -eq 1) {
        $Hotfix = Get-HotFix -Id KB4474419 -ErrorAction SilentlyContinue

        if (-not ($Hotfix)) {
            $Message = "Unable to run MSERT: KB4474419 is missing on Server 2008 R2"
            $RegMessage = "Unable to run MSERT KB4474419 missing"

            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }
    }

    #Check for running MSERT or MRT process before download
    $procsToWaitFor = @("mrt", "msert")
    :checkForRunningCleaner while ($true) {
        foreach ($procName in $procsToWaitFor) {
            $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($proc) {
                $pids = [string]::Join(",", $proc.Id)

                $Message = "Found $procName already running ($pids). Waiting for it to exit."
                $RegMessage = "msert already running waiting"
                $Stage = "MSERTProcess"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

                Start-Sleep -Seconds 60
                continue checkForRunningCleaner
            }
        }
        break
    }


    if ((Get-Item $env:TEMP).PSDrive.Free -ge 314572800) {
        if ([System.Environment]::Is64BitOperatingSystem) {
            $MSERTUrl = "https://go.microsoft.com/fwlink/?LinkId=212732"
        } else {
            $MSERTUrl = "https://go.microsoft.com/fwlink/?LinkId=212733"
        }

        $Message = "Starting MSERTProcess on $env:computername"
        $RegMessage = "Starting MSERTProcess"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        try {
            $msertExe = Join-Path $EOMTDir "\msert.exe"
            $response = Invoke-WebRequest $MSERTUrl -UseBasicParsing
            [IO.File]::WriteAllBytes($msertExe, $response.Content)

            $Message = "MSERT download complete on $env:computername"
            $RegMessage = "MSERT download complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } catch {
            $Message = "MSERT download failed on $env:computername"
            $RegMessage = "MSERT download failed"
            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }
    } else {
        $drive = (Get-Item $env:TEMP).PSDrive.Root
        $Message = "MSERT download failed on $env:computername, due to lack of space on $drive"
        $RegMessage = "MSERT did not download. Ensure there is at least 300MB of free disk space on $drive"
        Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
        throw
    }

    #Start MSERT
    function RunMsert {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Invalid rule result')]
        param(
            [switch]$FullScan
        )

        $msertLogPath = "$env:SystemRoot\debug\msert.log"
        $msertLogArchivePath = "$env:SystemRoot\debug\msert.old.log"

        if (Test-Path $msertLogPath) {
            Get-Content $msertLogPath | Out-File $msertLogArchivePath -Append
            Remove-Item $msertLogPath
        }

        $msertArguments = "/Q"
        if ($FullScan) {
            $msertArguments = "/F /Q"
        }

        Start-Process $msertExe -ArgumentList $msertArguments -Wait

        $detected = $false

        if (Test-Path $msertLogPath) {
            $matches = Select-String -Path $msertLogPath -Pattern "Threat Detected"
            if ($matches) {
                $detected = $true
            }
        } else {
            $Message = "Did not find expected scanner log file at $msertLogPath"
            $RegMessage = "No scanner log"
            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }

        return $detected
    }

    if ($RunFullScan) {
        Write-Warning -Message "Running a full scan can take hours or days to complete."
        Write-Warning -Message "Would you like to continue with the Full MSERT Scan?"

        while ($true) {
            $Confirm = Read-Host "(Y/N)"
            if ($Confirm -like "N") {
                return
            }
            if ($Confirm -like "Y") {
                break
            }
        }

        $Message = "Running Microsoft Safety Scanner - Mode: Full Scan on $env:computername"
        $RegMessage = "Running Microsoft Safety Scanner Full Scan"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $msertDetected = RunMsert -FullScan
    } else {
        Write-Verbose -Message "Quick scan will take several minutes to complete, please wait.." -Verbose

        $Message = "Running Microsoft Safety Scanner - Mode: Quick Scan on $env:computername"
        $RegMessage = "Running Microsoft Safety Scanner Quick Scan"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $msertDetected = RunMsert
    }

    if ($msertDetected) {
        Write-Warning -Message "THREATS DETECTED on $env:computername!"
        Get-Content $msertLogPath
        $Message = "Threats detected! Please review `"$msertLogPath`" as soon as possible. "
        if (!$RunFullScan) {
            $Message += "We highly recommend re-running this script with -RunFullScan. "
        }
        $Message += "For additional guidance, see `"$SummaryFile`"."
        $RegMessage = "Microsoft Safety Scanner is complete: THREATS DETECTED"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    } else {
        $Message = "Microsoft Safety Scanner is complete on $env:computername No known threats detected."
        $RegMessage = "Microsoft Safety Scanner is complete"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    }
}

function Get-ServerVulnStatus {

    $Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\').OwaVersion
    $FutureCUs = @{
        E19CU9  = "15.2.858.5"
        E16CU20 = "15.1.2242.4"
    }

    if ($version -like "15.2.*") {
        $LatestCU = $FutureCUs.E19CU9
    } elseif ($version -like "15.1.*") {
        $LatestCU = $FutureCUs.E16CU20
    } else {
        $LatestCU = "15.2.000.0000" #version higher than 15.0 to trigger SecurityHotfix check for E15
    }

    if ([version]$LatestCU -gt [version]$Version) {

        $SecurityHotfix = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* `
        | Where-Object displayname -Like "*KB5000871*" `
        | Select-Object displayname -ErrorAction SilentlyContinue

        if (!$SecurityHotfix) {
            return $true
        }
    }
    return $false
}

function Get-ExchangeUpdateInfo {
    $exchange2016CU20DownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=102896"
    $exchange2013CU23DownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=58392"
    $exchange2013CU23SecurityUpdateDownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=102775"

    $Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\').OwaVersion
    $Message = "For long-term protection, please use Microsoft Update to install the latest Security Update for Exchange Server (KB5000871)."

    if ($Version -like "15.2.*") {
        return $Message
    } elseif ($Version -like "15.1.*") {
        $Message += "`nIf you don't see this security update, please upgrade to Exchange 2016 Cumulative Update 20 via: $exchange2016CU20DownloadLink"
        return $Message
    } elseif ($Version -like "15.0.*") {
        $Message += "`nIf you don't see this security update, please upgrade to Exchange 2013 Cumulative Update 23 via: $exchange2013CU23DownloadLink"
        $Message += "`nAfter applying the cumulative update, you will also need to install the latest security update: $exchange2013CU23SecurityUpdateDownloadLink"
        return $Message
    }

    return  $null
}

function Write-Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Invalid rule result')]
    param
    (
        [string]$Message,
        [string]$Path = $EOMTLogFile,
        [string]$Level = "Info"
    )

    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Write log entry to $Path
    "$FormattedDate $($Level): $Message" | Out-File -FilePath $Path -Append
}

function Set-LogActivity {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Invalid rule result')]
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $Stage,
        $RegMessage,
        $Message,
        [switch] $Error,
        $ForegroundColor
    )

    if ($Error) {
        $FullRegMessage = "0 $RegMessage"
        $Level = "Error"
    } else {
        $FullRegMessage = "1 $RegMessage"
        $Level = "Info"
    }
    If ($Level -eq "Info") {
        If ($ForegroundColor) {
            Write-Host $Message -ForegroundColor $ForegroundColor
        } else {
            Write-Verbose -Message $Message -Verbose
        }
    } else {
        Write-Error -Message $Message
    }

    Write-Log -Message $Message -Level $Level
    Set-Registry -RegKey "HKLM:\Software\MSERTBootstrap\PatchState" -RegValue "Timestamp" -RegData (Get-Date).ToString("MM/dd/yyyy hh:mm:ss") -RegType String | Out-Null
    Set-Registry -RegKey "HKLM:\Software\MSERTBootstrap\PatchState" -RegValue $Stage -RegData $FullRegMessage -RegType String | Out-Null
}

function Set-Registry {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $RegKey,
        $RegValue,
        $RegData,
        [ValidateSet('String', 'DWord', 'Binary', 'ExpandString', 'MultiString', 'None', 'QWord', 'Unknown')]
        $RegType = 'String'
    )

    if (-not (Test-Path $RegKey)) {
        Write-Verbose "The key $RegKey does not exist. Trying to create it..."

        try {
            New-Item -Path $RegKey -Force
            Write-Verbose "Creation of $RegKey was successful."
        } catch {
            Write-Error -Message $_
            return
        }
    }
    Set-ItemProperty -Path $RegKey -Name "Timestamp" -Value (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") -Type $RegType -Force
    Set-ItemProperty -Path $RegKey -Name $RegValue -Value $RegData -Type $RegType -Force
}

function Write-Summary {
    param(
        [switch]$Pass
    )

    $UpdateInfo = Get-ExchangeUpdateInfo

    if ($Pass) {
        $header = @"
Microsoft Safety Scanner and CVE-2021-26855 mitigation summary
Message: Microsoft attempted to mitigate and protect your Exchange server from CVE-2021-26855 and clear malicious files.
For more information on these vulnerabilities please visit https://aka.ms/Exchangevulns.
Please review locations and files as soon as possible and take the recommended action.
"@
    } else {
        $header = @"
Microsoft Safety Scanner and CVE-2021-26855 mitigation summary
Message: Microsoft attempted to mitigate and protect your Exchange server from CVE-2021-26855 and clear malicious files.
For more information on these vulnerabilities please visit https://aka.ms/Exchangevulns. This attempt was unsuccessful.
Please review locations and files as soon as possible and take the recommended action.
"@
    }

    $summary = @"
$header

Microsoft saved several files to your system to "$EOMTDir". The only files that should be present in this directory are:
    a - msert.exe
    b - EOMT.log
    c - RewriteModuleInstall.log
    d - one of the following IIS URL rewrite MSIs:
        rewrite_amd64_[de-DE,en-US,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_ x86_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_x64_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_2.0_rtw_x86.msi
        rewrite_2.0_rtw_x64.msi

1 - Confirm the IIS URL Rewrite Module is installed. This module is required for the mitigation of CVE-2021-26855, the module and the configuration (present or not) will not impact this system negatively.
    a - If installed, Confirm the following entry exists in the "$env:SystemDrive\inetpub\wwwroot\web.config". If this configuration is not present, your server is not mitigated. This may have occurred if the module was not successfully installed with a supported version for your system.
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="X-AnonResource-Backend Abort - inbound">
                    <match url=".*" />
                    <conditions>
                        <add input="{HTTP_COOKIE}" pattern="(.*)X-AnonResource-Backend(.*)" />
                    </conditions>
                    <action type="AbortRequest" />
                </rule>
                <rule name="X-BEResource Abort - inbound" stopProcessing="true">
                    <match url=".*" />
                    <conditions>
                        <add input="{HTTP_COOKIE}" pattern="(.*)X-BEResource=(.+)/(.+)~(.+)" />
                    </conditions>
                    <action type="AbortRequest" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>

2 - Review the results of the Microsoft Safety Scanner
        Microsoft Safety Scanner log can be found at "$msertLogPath" and "$msertLogArchivePath" If any threats were detected, please review the guidance here: $detectionFollowUpURL

$UpdateInfo

"@

    if (Test-Path $SummaryFile) {
        Remove-Item $SummaryFile -Force
    }

    $summary = $summary.Replace("`r`n", "`n").Replace("`n", "`r`n")
    $summary | Out-File -FilePath $SummaryFile -Encoding ascii -Force
}

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Unable to launch EOMT.ps1: please re-run as administrator."
    exit
}

#supported Exchange check
if (!((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction 0).MsiInstallPath)) {
    Write-Error "A supported version of Exchange was not found on $env:computername. The Exchange On-premises Mitigation Tool supports Exchange 2013, 2016, and 2019."
    exit
}

# Main
try {
    $Stage = "EOMTStart"

    if (!(Test-Path $EOMTDir)) {
        New-Item -ItemType Directory $EOMTDir | Out-Null
    }

    $Message = "Starting EOMT.ps1 on $env:computername"
    $RegMessage = "Starting EOMT.ps1"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    #IsPS3 or later?
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        $Message = "Unsupported Powershell on $env:computername"
        $RegMessage = "Unsupported Powershell"
        Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
        throw
    }

    $Message = "EOMT precheck complete on $env:computername"
    $RegMessage = "EOMT precheck complete"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    #Execute Mitigation
    if ($DoNotRunMitigation) {
        $Stage = "DoNotRunMitigation"
        $Message = "Skipping mitigation -DoNotRunMitigation set on $env:computername"
        $RegMessage = "Skipping mitigation -DoNotRunMitigation"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    }

    if ($RollbackMitigation) {
        Run-Mitigate -RollbackMitigation
    }

    if (!$DoNotRunMitigation -and !$RollbackMitigation) {
        #Normal run
        $IsVulnerable = Get-ServerVulnStatus
        if ($IsVulnerable) {
            $Message = "$env:computername is vulnerable: applying mitigation"
            $RegMessage = "Server is vulnerable"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
            Run-Mitigate

            $Message = Get-ExchangeUpdateInfo
            if ($Message) {
                $RegMessage = "Prompt to apply updates"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -ForegroundColor Red
            }
        } else {
            $Message = "$env:computername is not vulnerable: mitigation not needed"
            $RegMessage = "Server is not vulnerable"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        }
    }

    #Execute Msert
    if ($RunFullScan) {
        Run-MSERT -RunFullScan
    } elseif (!$RollbackMitigation) {
        Run-MSERT
    }

    $Message = "EOMT.ps1 complete on $env:computername, please review EOMT logs at $EOMTLogFile and the summary file at $SummaryFile"
    $RegMessage = "EOMT.ps1 completed successfully"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -Pass #Pass
} catch {
    $Message = "EOMT.ps1 failed to complete on $env:computername, please review EOMT logs at $EOMTLogFile and the summary file at $SummaryFile - $_"
    $RegMessage = "EOMT.ps1 failed to complete"
    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary #Fail
}
