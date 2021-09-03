# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
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
        If set, will determine if the server is vulnerable and run MSERT in full scan mode.
    .PARAMETER RollbackMitigation
        If set, will only reverse the mitigations if present.
    .PARAMETER DoNotRunMSERT
        If set, will not run MSERT.
    .PARAMETER DoNotRunMitigation
        If set, will not apply mitigations.
    .PARAMETER DoNotRemediate
        If set, MSERT will not remediate detected threats.
    .PARAMETER DoNotAutoUpdateEOMT
        If set, will not attempt to download and run latest EOMT version from github.
    .EXAMPLE
		PS C:\> EOMT.ps1
		This will run the default mode which does the following:
            1. Checks if an updated version of EOMT is available, downloads and runs latest version if so
            2. Checks if your server is vulnerable based on the presence of the SU patch or Exchange version
            3. Downloads and installs the IIS URL rewrite tool.
            4. Applies the URL rewrite mitigation (only if vulnerable).
            5. Runs the Microsoft Safety Scanner in "Quick Scan" mode.
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

[Cmdletbinding()]
param (
    [switch]$RunFullScan,
    [switch]$RollbackMitigation,
    [switch]$DoNotRunMSERT,
    [switch]$DoNotRunMitigation,
    [switch]$DoNotRemediate,
    [switch]$DoNotAutoUpdateEOMT
)

$ProgressPreference = "SilentlyContinue"
$EOMTDir = Join-Path $env:TEMP "msert"
$EOMTLogFile = Join-Path $EOMTDir "EOMT.log"
$msertLogPath = "$env:SystemRoot\debug\msert.log"
$msertLogArchivePath = "$env:SystemRoot\debug\msert.old.log"
$detectionFollowUpURL = 'https://go.microsoft.com/fwlink/?linkid=2157359'
$SummaryFile = "$env:SystemDrive\EOMTSummary.txt"
$EOMTDownloadUrl = 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMT.ps1'
$versionsUrl = 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv'
$MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

#autopopulated by CSS-Exchange build
$BuildVersion = ""

# Force TLS1.2 to make sure we can download from HTTPS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Run-Mitigate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [string]$WebSiteName = "Default Web Site",
        [string]$Stage = "MitigationProcess",
        [switch]$RollbackMitigation

    )

    function Get-MsiProductVersion {
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

    function Get-URLRewriteLink {
        $DownloadLinks = @{
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

        return $DownloadLinks[$Architecture][$Language]
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

        $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

        if ($RewriteModule) {
            $Message = "IIS URL Rewrite Module is already installed on $env:computername"
            $RegMessage = "IIS URL Rewrite Module already installed"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $DownloadLink = Get-URLRewriteLink
            $DownloadPath = Join-Path $EOMTDir "\$($DownloadLink.Split("/")[-1])"
            $RewriteModuleInstallLog = Join-Path $EOMTDir "\RewriteModuleInstall.log"

            $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
            [IO.File]::WriteAllBytes($DownloadPath, $response.Content)

            $MSIProductVersion = Get-MsiProductVersion -filename $DownloadPath

            if ($MSIProductVersion -lt "7.2.1993") {
                $Message = "Incorrect IIS URL Rewrite Module downloaded on $env:computername"
                $RegMessage = "Incorrect IIS URL Rewrite Module downloaded"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
            #KB2999226 required for IIS Rewrite 2.1 on IIS ver under 10
            if (!(Test-IIS10) -and !(Get-HotFix -Id "KB2999226" -ErrorAction SilentlyContinue)) {
                $Message = "Did not detect the KB2999226 on $env:computername. Please review the pre-reqs for this KB and download from https://support.microsoft.com/en-us/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c"
                $RegMessage = "Did not detect KB299226"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }

            $Message = "Installing the IIS URL Rewrite Module on $env:computername"
            $RegMessage = "Installing IIS URL Rewrite Module"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

            $arguments = "/i `"$DownloadPath`" /quiet /log `"$RewriteModuleInstallLog`""
            $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"

            if (!(Confirm-Signature -filepath $DownloadPath -Stage $stage)) {
                $Message = "File present at $DownloadPath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for UrlRewrite MSI does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }

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
        [switch]$RunFullScan,
        [switch]$DoNotRemediate
    )
    $Stage = "MSERTProcess"
    if ($DoNotRunMSERT) {
        $Message = "Skipping MSERT scan -DoNotRunMSERT set on $env:computername"
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
            [switch]$FullScan,
            [switch]$DoNotRemediate
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

        if ($DoNotRemediate) {
            $msertArguments += " /N"
        }

        if (!(Confirm-Signature -filepath $msertExe -Stage $stage)) {
            $Message = "File present at $msertExe does not seem to be signed as expected, stopping execution."
            $RegMessage = "File downloaded for MSERT does not seem to be signed as expected, stopping execution"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
            Write-Summary -NoRemediation:$DoNotRemediate
            throw
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

    $ScanMode = ""
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

        $ScanMode = "Full Scan"
    } else {
        Write-Verbose -Message "Quick scan will take several minutes to complete, please wait.." -Verbose

        $ScanMode = "Quick Scan"
    }

    if ($DoNotRemediate) {
        $ScanMode += " (No Remediation)"
    }

    $Message = "Running Microsoft Safety Scanner - Mode: $ScanMode on $env:computername"
    $RegMessage = "Running Microsoft Safety Scanner $ScanMode"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    $msertDetected = RunMsert -FullScan:$RunFullScan -DoNotRemediate:$DoNotRemediate

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

function Get-ExchangeVersion () {
    $setup = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\)
    $version = New-Object -Type System.Version -ArgumentList ($setup.MsiProductMajor, $setup.MsiProductMinor, $setup.MsiBuildMajor, $setup.MsiBuildMinor)
    $version
}

function Get-ServerPatchStatus {
    $FutureCUs = @{
        E19CU9  = "15.2.858.5"
        E16CU20 = "15.1.2242.4"
    }

    $PatchStatus = @{
        KB5000871 = $false
        LatestCU  = $false
    }

    $Version = Get-ExchangeVersion
    if ($Version.Major -eq 15 -and $Version.Minor -eq 2) {
        $LatestCU = $FutureCUs.E19CU9
    } elseif ($Version.Major -eq 15 -and $Version.Minor -eq 1) {
        $LatestCU = $FutureCUs.E16CU20
    } else {
        $LatestCU = "15.1.000.0000" #version higher than 15.0 to trigger SecurityHotfix check for E15
    }

    $KBregex = "[0-9]{7}"

    [long]$LatestInstalledExchangeSU = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object displayname -Like "Security Update for Exchange Server*" |
            Select-Object displayname |
            Select-String -Pattern $KBregex).Matches.Value

    if ($Version -ge [version]$LatestCU) {
        #They have the March CU, which contains this KB
        $PatchStatus["LatestCU"] = $true
        $PatchStatus["KB5000871"] = $true
    } elseif ($Version -lt [version]$LatestCU) {
        #They don't have March CU
        if ($LatestInstalledExchangeSU -ge 5000871) {
            $PatchStatus["KB5000871"] = $true
        }
    }
    return $PatchStatus
}

function Get-ExchangeUpdateInfo {
    $exchange2019CU9DownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=102900"
    $exchange2016CU20DownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=102896"
    $exchange2013CU23DownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=58392"
    $exchange2013CU23SecurityUpdateDownloadLink = "https://www.microsoft.com/en-us/download/details.aspx?id=102775"

    $Version = Get-ExchangeVersion
    $Message = "For long-term protection, please use Microsoft Update to install the latest Security Update for Exchange Server (KB5000871)."

    if ($Version.Major -eq 15 -and $Version.Minor -eq 2) {
        $Message += "`nIf you don't see this security update, please upgrade to Exchange 2019 Cumulative Update 9 via: $exchange2019CU9DownloadLink"
        return $Message
    } elseif ($Version.Major -eq 15 -and $Version.Minor -eq 1) {
        $Message += "`nIf you don't see this security update, please upgrade to Exchange 2016 Cumulative Update 20 via: $exchange2016CU20DownloadLink"
        return $Message
    } elseif ($Version.Major -eq 15 -and $Version.Minor -eq 0) {
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
        [switch]$Notice,
        [switch]$Error
    )
    if ($Notice) {
        $FullRegMessage = "1 $RegMessage"
        $Level = "Notice"
    } elseif ($Error) {
        $FullRegMessage = "0 $RegMessage"
        $Level = "Error"
    } else {
        $FullRegMessage = "1 $RegMessage"
        $Level = "Info"
    }
    If ($Level -eq "Info") {
        Write-Verbose -Message $Message -Verbose
    } elseif ($Level -eq "Notice") {
        Write-Host -ForegroundColor Cyan -BackgroundColor black "NOTICE: $Message"
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

function Confirm-Signature {
    param(
        [string]$Filepath,
        [string]$Stage
    )

    $IsValid = $false
    $failMsg = "Signature of $Filepath not as expected. "
    try {
        if (!(Test-Path $Filepath)) {
            $IsValid = $false
            $failMsg += "Filepath does not exist"
            throw
        }

        $sig = Get-AuthenticodeSignature -FilePath $Filepath

        if ($sig.Status -ne 'Valid') {
            $IsValid = $false
            $failMsg += "Signature is not trusted by machine as Valid, status: $($sig.Status)"
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        $chainsCorrectly = $chain.Build($sig.SignerCertificate)

        if (!$chainsCorrectly) {
            $IsValid = $false
            $failMsg += "Signer certificate doesn't chain correctly"
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            $IsValid = $false
            $failMsg += "Certificate Chain shorter than expected"
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            $IsValid = $false
            $failMsg += "Top-level certifcate in chain is not a root certificate"
            throw
        }

        if ($rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2010 -or $rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2011) {
            $IsValid = $true
            $Message = "$Filepath is signed by Microsoft as expected, trusted by machine as Valid, signed by: $($sig.SignerCertificate.Subject), Issued by: $($sig.SignerCertificate.Issuer), with Root certificate: $($rootCert.Certificate.Subject)"
            $RegMessage = "$Filepath is signed by Microsoft as expected"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $IsValid = $false
            $failMsg += "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)"
            throw
        }
    } catch {
        $IsValid = $false
        Set-LogActivity -Stage $Stage -RegMessage $failMsg -Message $failMsg -Error
    }

    return $IsValid
}
function Write-Summary {
    param(
        [switch]$Pass,
        [switch]$NoRemediation
    )

    $UpdateInfo = Get-ExchangeUpdateInfo

    $RemediationText = ""
    if (!$NoRemediation) {
        $RemediationText = " and clear malicious files"
    }

    $FailureText = ""
    if (!$Pass) {
        $FailureText = " This attempt was unsuccessful."
    }

    $summary = @"
Microsoft Safety Scanner and CVE-2021-26855 mitigation summary
Message: Microsoft attempted to mitigate and protect your Exchange server from CVE-2021-26855$RemediationText.
For more information on these vulnerabilities please visit https://aka.ms/Exchangevulns.$FailureText
Please review locations and files as soon as possible and take the recommended action.
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

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "Unsupported version of PowerShell on $env:computername - The Exchange On-premises Mitigation Tool supports PowerShell 3 and later"
    exit
}

#supported Exchange check
if (!((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction 0).MsiInstallPath)) {
    Write-Error "A supported version of Exchange was not found on $env:computername. The Exchange On-premises Mitigation Tool supports Exchange 2013, 2016, and 2019."
    exit
}

# Main
try {
    $Stage = "CheckEOMTVersion"

    if (!(Test-Path $EOMTDir)) {
        New-Item -ItemType Directory $EOMTDir | Out-Null
    }

    try {
        $Message = "Checking if EOMT is up to date with $versionsUrl"
        Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
        $latestEOMTVersion = $null
        $versionsData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $versionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
        $latestEOMTVersion = ($versionsData | Where-Object -Property File -EQ "EOMT.ps1").Version
    } catch {
        $Message = "Cannot check version info at $versionsUrl to confirm EOMT.ps1 is latest version. Version currently running is $BuildVersion. Please download latest EOMT from $EOMTDownloadUrl and re-run EOMT, unless you just did so. Exception: $($_.Exception)"
        $RegMessage = "Cannot check version info at $versionsUrl to confirm EOMT.ps1 is latest version. Version currently running is $BuildVersion. Continuing with execution"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
    }

    $DisableAutoupdateIfneeded = "If you are getting this error even with updated EOMT, re-run with -DoNotAutoUpdateEOMT parameter";

    $Stage = "AutoupdateEOMT"
    if ($latestEOMTVersion -and ($BuildVersion -ne $latestEOMTVersion)) {
        if ($DoNotAutoUpdateEOMT) {
            $Message = "EOMT.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTVersion. We strongly recommend downloading latest EOMT from $EOMTDownloadUrl and re-running EOMT. DoNotAutoUpdateEOMT is set, so continuing with execution"
            $RegMessage = "EOMT.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTVersion.  DoNotAutoUpdateEOMT is set, so continuing with execution"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $Stage = "DownloadLatestEOMT"
            $eomtLatestFilepath = Join-Path $EOMTDir "EOMT_$latestEOMTVersion.ps1"
            try {
                $Message = "Downloading latest EOMT from $EOMTDownloadUrl"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
                Invoke-WebRequest $EOMTDownloadUrl -OutFile $eomtLatestFilepath -UseBasicParsing
            } catch {
                $Message = "Cannot download latest EOMT.  Please download latest EOMT yourself from $EOMTDownloadUrl, copy to necessary machine(s), and re-run. $DisableAutoupdateIfNeeded. Exception: $($_.Exception)"
                $RegMessage = "Cannot download latest EOMT from $EOMTDownloadUrl. Stopping execution."
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                throw
            }

            $Stage = "RunLatestEOMT"
            if (Confirm-Signature -Filepath $eomtLatestFilepath -Stage $Stage) {
                $Message = "Running latest EOMT version $latestEOMTVersion downloaded to $eomtLatestFilepath"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message

                try {
                    & $eomtLatestFilepath @PSBoundParameters
                    Exit
                } catch {
                    $Message = "Run failed for latest EOMT version $latestEOMTVersion downloaded to $eomtLatestFilepath, please re-run $eomtLatestFilepath manually. $DisableAutoupdateIfNeeded. Exception: $($_.Exception)"
                    $RegMessage = "Run failed for latest EOMT version $latestEOMTVersion"
                    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                    throw
                }
            } else {
                $Message = "File downloaded to $eomtLatestFilepath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for EOMT.ps1 does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }
        }
    }

    $Stage = "EOMTStart"

    $Message = "Starting EOMT.ps1 version $BuildVersion on $env:computername"
    $RegMessage = "Starting EOMT.ps1 version $BuildVersion"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

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
        $PatchStatus = Get-ServerPatchStatus
        if ($PatchStatus["KB5000871"] -eq $false) {
            $IsVulnerable = $True
        } else {
            $IsVulnerable = $False
        }
        if ($IsVulnerable) {
            $Message = "$env:computername is vulnerable: applying mitigation"
            $RegMessage = "Server is vulnerable"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
            Run-Mitigate

            $Message = Get-ExchangeUpdateInfo
            if ($Message) {
                $RegMessage = "Prompt to apply updates"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
            }
        } else {
            $Message = "$env:computername is not vulnerable: mitigation not needed"
            $RegMessage = "Server is not vulnerable"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        }
    }

    #Execute Msert
    if ($RunFullScan) {
        Run-MSERT -RunFullScan -DoNotRemediate:$DoNotRemediate
    } elseif (!$RollbackMitigation) {
        Run-MSERT -DoNotRemediate:$DoNotRemediate
    }

    $Message = "EOMT.ps1 complete on $env:computername, please review EOMT logs at $EOMTLogFile and the summary file at $SummaryFile"
    $RegMessage = "EOMT.ps1 completed successfully"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -Pass -NoRemediation:$DoNotRemediate #Pass
} catch {
    $Message = "EOMT.ps1 failed to complete on $env:computername, please review EOMT logs at $EOMTLogFile and the summary file at $SummaryFile - $_"
    $RegMessage = "EOMT.ps1 failed to complete"
    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -NoRemediation:$DoNotRemediate #Fail
}
