<#
    .SYNOPSIS
		This script contains 4 mitigations to help address the following vulnerabilities:

        CVE-2021-26855
        CVE-2021-26857
        CVE-2021-27065
        CVE-2021-26858

        For more information on each mitigation please visit https://aka.ms/exchangevulns

	.DESCRIPTION
        For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 (x86 and x64) here:
        * x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite

        For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:
        * x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747

        * x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435

        It is important to follow these version guidelines as it was found installing the newer version of the URL rewrite module on older versions of IIS (IIS 8.5 and lower) can cause IIS and Exchange to become unstable.
        If you find yourself in a scenario where a newer version of the IIS URL rewrite module was installed on an older version of IIS, uninstalling the URL rewrite module and reinstalling the recommended version listed above should resolve any instability issues.

	.PARAMETER FullPathToMSI
        This is string parameter is used to specify path of MSI file of URL Rewrite Module.

    .PARAMETER WebSiteNames
        This is string parameter is used to specify name of Default Web Site.

    .PARAMETER ApplyAllMitigations
        This is a switch parameter is used to apply all 4 mitigations: BackendCookieMitigation, UnifiedMessagingMitigation, ECPAppPoolMitigation and OABAppPoolMitigation in one go.

    .PARAMETER RollbackAllMitigations
        This is a switch parameter is used to rollback all 4 mitigations: BackendCookieMitigation, UnifiedMessagingMitigation, ECPAppPoolMitigation and OABAppPoolMitigation in one go.

    .PARAMETER ApplyBackendCookieMitigation
        This is a switch parameter is used to apply the Backend Cookie Mitigation

    .PARAMETER RollbackBackendCookieMitigation
        This is a switch parameter is used to roll back the Backend Cookie Mitigation

    .PARAMETER ApplyUnifiedMessagingMitigation
        This is a switch parameter is used to apply the Unified Messaging Mitigation

    .PARAMETER RollbackUnifiedMessagingMitigation
        This is a switch parameter is used to roll back the Unified Messaging Mitigation

    .PARAMETER ApplyECPAppPoolMitigation
        This is a switch parameter is used to apply the ECP App Pool Mitigation

    .PARAMETER RollbackECPAppPoolMitigation
        This is a switch parameter is used to roll back the ECP App Pool Mitigation

    .PARAMETER ApplyOABAppPoolMitigation
        This is a switch parameter is used to apply the OAB App Pool Mitigation

    .PARAMETER RollbackOABAppPoolMitigation
        This is a switch parameter is used to roll back the OAB App Pool Mitigation

    .PARAMETER operationTimeOutDuration
        operationTimeOutDuration is the max duration (in seconds) we wait for each mitigation/rollback before timing it out and throwing.

    .PARAMETER AutoDownloadURLRewrite
        If set will automatically download/install the IIS URL Rewrite Module.

     .PARAMETER Verbose
        The Verbose switch can be used to view the changes that occurs during script execution.

	.EXAMPLE
		PS C:\> ExchangeMitigations.ps1 -FullPathToMSI "FullPathToMSI" -WebSiteNames "Default Web Site" -ApplyAllMitigations -Verbose

		To apply all mitigations and install the IIS URL Rewrite Module.

    .EXAMPLE
		PS C:\> ExchangeMitigations.ps1 -AutoDownloadURLRewrite -WebSiteNames "Default Web Site" -ApplyAllMitigations -Verbose

		To apply all mitigations, download, and install the IIS URL Rewrite Module.

	.EXAMPLE
		PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyAllMitigation -Verbose

        To apply all mitigations without installing the IIS URL Rewrite Module.

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackAllMitigations -Verbose

        To rollback all mitigations

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -ApplyECPAppPoolMitigation -ApplyOABAppPoolMitigation -Verbose

        To apply multiple mitigations (out of the 4)

    .EXAMPLE
        PS C:\> ExchangeMitigations.ps1 -WebSiteNames "Default Web Site" -RollbackECPAppPoolMitigation -RollbackOABAppPoolMitigation -Verbose

        To rollback multiple mitigations (out of the 4)

    .Link
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://www.microsoft.com/en-us/download/details.aspx?id=5747
        https://www.microsoft.com/en-us/download/details.aspx?id=7435
#>

[CmdLetBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
param(
    [switch]$ApplyAllMitigations,
    [switch]$ApplyBackendCookieMitigation,
    [switch]$ApplyUnifiedMessagingMitigation,
    [switch]$ApplyECPAppPoolMitigation,
    [switch]$ApplyOABAppPoolMitigation,
    [switch]$RollbackAllMitigations,
    [switch]$RollbackBackendCookieMitigation,
    [switch]$RollbackUnifiedMessagingMitigation,
    [switch]$RollbackECPAppPoolMitigation,
    [switch]$RollbackOABAppPoolMitigation,
    [int]$operationTimeOutDuration = 120,
    [ValidateNotNullOrEmpty()][string[]]$WebSiteNames = $(throw "WebSiteNames is mandatory, please provide valid value."),
    [System.IO.FileInfo]$FullPathToMSI,
    [switch]$AutoDownloadURLRewrite
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

    $IISVersion = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ | Select-Object versionstring

    if ($IISVersion.VersionString -like "* 10.*") {
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
Function BackendCookieMitigation {
    [CmdLetBinding()]
    param(
        [System.IO.FileInfo]$FullPathToMSI,
        [ValidateNotNullOrEmpty()]
        [string[]]$WebSiteNames,
        [switch]$RollbackMitigation
    )

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

    if (!$RollbackMitigation) {
        Write-Verbose "[INFO] Starting mitigation process on $env:computername" -Verbose

        #Check if IIS URL Rewrite Module 2 is installed
        Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername" -Verbose

        #If IIS 10 check for URL rewrite 2.1 else URL rewrite 2.0
        $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"
        $IISVersion = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ | Select-Object versionstring

        $RewriteModuleInstallLog = ($PSScriptRoot + '\' + 'RewriteModuleInstallLog.log')

        #Install module
        if ($RewriteModule) {

            #Throwing an exception if incorrect rewrite module version is installed
            if ($IISVersion.VersionString -like "*10.*" -and ($RewriteModule.Version -eq "7.2.2")) {
                throw "Incorrect IIS URL Rewrite Module 2.0 Installed. You need to install IIS URL Rewrite Module 2.1 to avoid instability issues."
            }
            if ($IISVersion.VersionString -notlike "*10.*" -and ($RewriteModule.Version -eq "7.2.1993")) {
                throw "Incorrect IIS URL Rewrite Module 2.1 Installed. You need to install IIS URL Rewrite Module 2.0 to avoid instability issues."
            }

            Write-Verbose "[INFO] IIS URL Rewrite Module 2 already installed on $env:computername" -Verbose
        } else {

            #IfAutoDownloadURLRewrite
            if ($AutoDownloadURLRewrite) {
                Write-Verbose -Message "ExchangeMitigations.ps1 will now attempt to download and install the IIS URL Rewrite Module on $env:computername" -Verbose
                try {
                    # Force TLS1.2 to make sure we can download from HTTPS
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    $ProgressPreference = "SilentlyContinue"
                    $DownloadDir = Join-Path $env:TEMP "IISUrlRewrite"
                    $DownloadLink = GetURLRewriteLink
                    $FullPathToMSI = Join-Path $DownloadDir "\$($DownloadLink.Split("/")[-1])"
                    if (!(Test-Path $DownloadDir)) {
                        New-Item -ItemType Directory $DownloadDir | Out-Null
                    }
                    Write-Verbose -Message "Downloading IIS URLRewrite MSI here: $FullPathToMSI" -Verbose
                    $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
                    [IO.File]::WriteAllBytes($FullPathToMSI, $response.Content)
                } catch {
                    throw $_
                }
            }

            if ($FullPathToMSI) {

                $MSIProductVersion = GetMsiProductVersion -filename $FullPathToMSI

                #If IIS 10 assert URL rewrite 2.1 else URL rewrite 2.0
                if ($IISVersion.VersionString -like "*10.*" -and $MSIProductVersion -eq "7.2.2") {
                    throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.1"
                }
                if ($IISVersion.VersionString -notlike "*10.*" -and $MSIProductVersion -eq "7.2.1993") {
                    throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.0"
                }

                Write-Verbose "[INFO] Installing IIS URL Rewrite Module 2" -Verbose
                $arguments = " /i " + '"' + $FullPathToMSI.FullName + '"' + " /quiet /log " + '"' + $RewriteModuleInstallLog + '"'
                $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"
                Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
                Start-Sleep -Seconds 15
                $RewriteModule = Get-InstalledSoftware -Name *IIS* | Where-Object { $_.Name -like "*URL*" -and $_.Name -like "*2*" }
                if ($RewriteModule) {
                    Write-Verbose "[OK] IIS URL Rewrite Module 2 installed on $env:computername"
                } else {
                    throw "[ERROR] Issue installing IIS URL Rewrite Module 2, please review $($RewriteModuleInstallLog)"
                }
            } else {
                throw "[ERROR] Unable to proceed on $env:computername, path to IIS URL Rewrite Module MSI not provided and module is not installed."
            }
        }

        foreach ($website in $WebSiteNames) {
            Write-Verbose "[INFO] Applying rewrite rule configuration to $env:COMPUTERNAME :: $website"

            $site = "IIS:\Sites\$($website)"

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

                Write-Verbose "[OK] Rewrite rule configuration complete for $env:COMPUTERNAME :: $website"
                Get-WebConfiguration -Filter $filter -PSPath $site
                Get-WebConfiguration -Filter $filter2 -PSPath $site
            } catch {
                throw $_
            }
        }
    } else {
        Write-Verbose "[INFO] Starting mitigation rollback process on $env:computername"
        foreach ($website in $WebSiteNames) {

            $site = "IIS:\Sites\$($website)"

            $MitigationConfig = Get-WebConfiguration -Filter $filter -PSPath $site
            if ($MitigationConfig) {
                Clear-WebConfiguration -Filter $filter -PSPath $site
                Clear-WebConfiguration -Filter $filter2 -PSPath $site

                $Rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' -Recurse
                if ($null -eq $Rules) {
                    Clear-WebConfiguration -PSPath $site -Filter 'system.webServer/rewrite/rules'
                }
                Write-Verbose "[OK] Rewrite rule mitigation removed for $env:COMPUTERNAME :: $website"
            } else {
                Write-Verbose "[INFO] Rewrite rule mitigation does not exist for $env:COMPUTERNAME :: $website"
            }
        }
    }
}
Function UnifiedMessagingMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )

    # UM doesn't apply to Exchange Server 2019
    $exchangeVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\')
    if ($exchangeVersion.OwaVersion -notmatch "15\.[01]") {
        Write-Verbose "[INFO] Skipping UM Mitigation for Exchange 2019"
        return
    }

    if ($ApplyMitigation) {

        StopAndCheckHM
        Stop-Service MSExchangeUM
        Set-Service MSExchangeUM -StartupType Disabled
        Stop-Service MSExchangeUMCR
        Set-Service MSExchangeUMCR -StartupType Disabled

        CheckOperationSuccess -conditions '((Get-Service MSExchangeUM).Status -eq "Stopped") -and `
                                           ((Get-Service MSExchangeUMCR).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUM"}).StartMode -eq "Disabled" ) -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUMCR"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Unified Messaging Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
        Get-Service MSExchangeUM
        Get-Service MSExchangeUMCR
    }
    if ($RollbackMitigation) {

        if (-not(((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped") -or ((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped"))) {
            StartAndCheckHM
        }
        Set-Service MSExchangeUM -StartupType Automatic
        Start-Service MSExchangeUM
        Set-Service MSExchangeUMCR -StartupType Automatic
        Start-Service MSExchangeUMCR

        CheckOperationSuccess -conditions '((Get-Service MSExchangeUM).Status -eq "Running") -and `
                                           ((Get-Service MSExchangeUMCR).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUM"}).StartMode -eq "Auto" ) -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeUMCR"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Unified Messaging Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
        Get-Service MSExchangeUM
        Get-Service MSExchangeUMCR
    }
}
Function ECPAppPoolMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )
    if ($ApplyMitigation) {
        StopAndCheckHM
        Import-Module WebAdministration
        $AppPoolName = "MSExchangeECPAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $false
        $AppPool | Set-Item -Verbose
        if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
            Stop-WebAppPool -Name $AppPoolName
        }

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped")' `
            -unSuccessfullMessage 'ECPAppPool Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
    if ($RollbackMitigation) {
        $exchangeVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\')
        if ($exchangeVersion.OwaVersion -notlike "15.0.*") {
            if (-not((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped")) {
                StartAndCheckHM
            }
        } else {

            if (-not( ((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped") -or ((Get-Service MSExchangeUM).Status -eq "Stopped") -or ((Get-Service MSExchangeUMCR).Status -eq "Stopped"))) {
                StartAndCheckHM
            }
        }

        Import-Module WebAdministration
        $AppPoolName = "MSExchangeECPAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $true
        $AppPool | Set-Item -Verbose
        Start-WebAppPool -Name $AppPoolName

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Started")' `
            -unSuccessfullMessage 'ECPAppPool Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
}
Function OABAppPoolMitigation {
    [CmdLetBinding()]
    param(
        [switch]$ApplyMitigation,
        [switch]$RollbackMitigation
    )
    if ($ApplyMitigation) {
        StopAndCheckHM
        Import-Module WebAdministration
        $AppPoolName = "MSExchangeOABAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $false
        $AppPool | Set-Item -Verbose
        if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne "Stopped") {
            Stop-WebAppPool -Name $AppPoolName
        }

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Stopped")' `
            -unSuccessfullMessage 'OABAppPool Mitigation Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
    if ($RollbackMitigation) {

        $exchangeVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\')
        if ($exchangeVersion.OwaVersion -notlike "15.0.*") {
            if (-not((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped")) {
                StartAndCheckHM
            }
        } else {

            if (-not( ((Get-WebAppPoolState -Name "MSExchangeECPAppPool").value -eq "Stopped") -or ((Get-Service MSExchangeUM).Status -eq "Stopped") -or ((Get-Service MSExchangeUMCR).Status -eq "Stopped"))) {
                StartAndCheckHM
            }
        }

        Import-Module WebAdministration
        $AppPoolName = "MSExchangeOABAppPool"
        $AppPool = Get-Item IIS:\AppPools\$AppPoolName
        $AppPool.startMode = "OnDemand"
        $AppPool.autoStart = $true
        $AppPool | Set-Item -Verbose
        Start-WebAppPool -Name $AppPoolName

        CheckOperationSuccess -conditions '((Get-WebAppPoolState -Name "MSExchangeOABAppPool").value -eq "Started")' `
            -unSuccessfullMessage 'OABAppPool Rollback Failed. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'

        Write-Verbose "Status of $AppPoolName" -Verbose
        Get-WebAppPoolState -Name $AppPoolName
    }
}
Function CheckOperationSuccess {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'TBD')]
    param(
        [string]$conditions,
        [string]$unSuccessfullMessage
    )

    $operationSuccessful = $false
    $attemptNumber = 0

    DO {
        Start-Sleep -Seconds 1
        $operationSuccessful = Invoke-Expression $conditions
        $attemptNumber += 1
    } While ( (-not $operationSuccessful) -and $attemptNumber -le $operationTimeOutDuration )

    if ( -not $operationSuccessful ) {
        throw $unSuccessfullMessage
    }
}
Function StopAndCheckHM {

    $MSExchangeHM = Get-Service MSExchangeHM
    if ($MSExchangeHM.Status -ne "Stopped") {
        Stop-Service MSExchangeHM
    }
    If (((gwmi -Class win32_service | Where-Object { $_.name -eq "msexchangehm" }).StartMode -ne "Disabled" )) {
        Set-Service MSExchangeHM -StartupType Disabled
    }

    $exchangeVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\')
    if ($exchangeVersion.OwaVersion -notlike "15.0.*") {

        $MSExchangeHMR = Get-Service MSExchangeHMRecovery
        if ($MSExchangeHMR.Status -ne "Stopped") {
            Stop-Service MSExchangeHMRecovery
        }
        If (((gwmi -Class win32_service | Where-Object { $_.name -eq "MSExchangeHMRecovery" }).StartMode -ne "Disabled")) {
            Set-Service MSExchangeHMRecovery -StartupType Disabled
        }

        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Disabled" ) -and `
                                           ((Get-Service MSExchangeHMRecovery).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeHMRecovery"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Mitigation Failed. HealthMonitoring or HealthMonitoringRecovery Service is running/not disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    } else {
        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Stopped") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Disabled" )' `
            -unSuccessfullMessage 'Mitigation Failed. HealthMonitoring Service is running/not disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    }

    Get-Service MSExchangeHM
    if ($exchangeVersion.OwaVersion -notlike "15.0.*") {
        Get-Service MSExchangeHMRecovery
    }
}
Function StartAndCheckHM {

    $MSExchangeHM = Get-Service MSExchangeHM
    If (((gwmi -Class win32_service | Where-Object { $_.name -eq "msexchangehm" }).StartMode -ne "Auto" )) {
        Set-Service MSExchangeHM -StartupType Automatic
    }
    if ($MSExchangeHM.Status -ne "Running") {
        Start-Service MSExchangeHM
    }

    $exchangeVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\')
    if ($exchangeVersion.OwaVersion -notlike "15.0.*") {

        $MSExchangeHMR = Get-Service MSExchangeHMRecovery
        If (((gwmi -Class win32_service | Where-Object { $_.name -eq "MSExchangeHMRecovery" }).StartMode -ne "Auto" )) {
            Set-Service MSExchangeHMRecovery -StartupType Automatic
        }
        if ($MSExchangeHMR.Status -ne "Running") {
            Start-Service MSExchangeHMRecovery
        }

        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Auto" ) -and `
                                           ((Get-Service MSExchangeHMRecovery).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "MSExchangeHMRecovery"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Rollback Failed. HealthMonitoring or HealthMonitoringRecovery Service is stopped/disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    } else {
        CheckOperationSuccess -conditions '((Get-Service MSExchangeHM).Status -eq "Running") -and `
                                           ((gwmi -Class win32_service |  ? {$_.name -eq "msexchangehm"}).StartMode -eq "Auto" )' `
            -unSuccessfullMessage 'Rollback Failed. HealthMonitoring Service is stopped/disabled. You can increase time out duration by adding -operationTimeOutDuration <timeInSeconds>'
    }

    Get-Service MSExchangeHM

    if ($exchangeVersion.OwaVersion -notlike "15.0.*") {
        Get-Service MSExchangeHMRecovery
    }
}


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script must be executed as administrator, please close and re-run Exchange Mangement Shell as administrator"
    return
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    throw "PowerShell does not meet the minimum requirements, system must have PowerShell 3 or later"
}

Import-Module WebAdministration
if ($ApplyAllMitigations -or $ApplyBackendCookieMitigation) {
    if ($FullPathToMSI) {
        BackendCookieMitigation -FullPathToMSI $FullPathToMSI -WebSiteNames $WebSiteNames -ErrorAction Stop
    } else {
        BackendCookieMitigation -WebSiteNames $WebSiteNames -ErrorAction Stop
    }
}
if ($RollbackAllMitigations -or $RollbackBackendCookieMitigation) {
    BackendCookieMitigation -WebSiteNames $WebSiteNames -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyUnifiedMessagingMitigation) {
    UnifiedMessagingMitigation -ApplyMitigation -ErrorAction Stop
}
if ($RollbackAllMitigations -or $RollbackUnifiedMessagingMitigation) {
    UnifiedMessagingMitigation -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyECPAppPoolMitigation) {
    ECPAppPoolMitigation -ApplyMitigation -ErrorAction Stop
}
if ($RollbackAllMitigations -or $RollbackECPAppPoolMitigation) {
    ECPAppPoolMitigation -RollbackMitigation -ErrorAction Stop
}

if ($RollbackAllMitigations -or $RollbackOABAppPoolMitigation) {
    OABAppPoolMitigation -RollbackMitigation -ErrorAction Stop
}
if ($ApplyAllMitigations -or $ApplyOABAppPoolMitigation) {
    OABAppPoolMitigation -ApplyMitigation -ErrorAction Stop
}
