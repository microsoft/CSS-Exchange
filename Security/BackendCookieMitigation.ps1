<#
    .SYNOPSIS
        This script contains a mitigation for CVE-2021-26855
        For more information please https://aka.ms/exchangevulns

	.DESCRIPTION
		This mitigation will filter https requests that contain malicious X-AnonResource-Backend and malformed X-BEResource cookies which were found to be used in cve2021-26855.
        This will help with defense against the known patterns observed but not the SSRF as a whole.

        For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 (x86 and x64) here:

        * x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite

        For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:

        * x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747

        * x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435

        It is important to follow these version guidelines as it was found installing the newer version of the URL rewrite module on older versions of IIS (IIS 8.5 and lower) can cause IIS and Exchange to become unstable.
        If you find yourself in a scenario where a newer version of the IIS URL rewrite module was installed on an older version of IIS, uninstalling the URL rewrite module and reinstalling the recommended version listed above should resolve any instability issues.

        Script requires PowerShell 3.0 and later and must be executed from an elevated PowerShell Session.

	.PARAMETER FullPathToMSI
        This is string parameter is used to specify path of MSI file of URL Rewrite Module.

    .PARAMETER WebSiteNames
        This is string array parameter is used to specify name of the Default Web Site in IIS.

    .PARAMETER RollbackMitigation
        This is a switch parameter is used to roll back the Backend Cookie Mitigation

	.EXAMPLE
		PS C:\> BackendCookieMitigation.ps1 -FullPathToMSI "C:\temp\rewrite_amd64_en-US.msi" -WebSiteNames "Default Web Site" -Verbose

		To apply with MSI install of the URL Rewrite module - Note: version may vary depending on system info

	.EXAMPLE
		PS C:\> BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -Verbose

		To apply without MSI install

    .EXAMPLE
        PS C:\> BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -RollbackMitigation -Verbose

        To rollback - Note: This does not remove the IIS Rewrite module, only the rules.

    .LINK
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
#>

[CmdLetBinding()]
param(
    [System.IO.FileInfo]$FullPathToMSI,
    [ValidateNotNullOrEmpty()]
    [string[]]$WebSiteNames,
    [switch]$RollbackMitigation
)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script must be executed as administrator, please close and re-run Exchange Mangement Shell as administrator"
    return
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    throw "PowerShell does not meet the minimum requirements, system must have PowerShell 3 or later"
}

Import-Module WebAdministration

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
    Write-Verbose "[INFO] Starting mitigation process on $env:computername"

    #Check if IIS URL Rewrite Module 2 is installed
    Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername"
    $IISRewriteQuery = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9BCA2118-F753-4A1E-BCF3-5A820729965C}' -ErrorAction SilentlyContinue).DisplayName

    $RewriteModuleInstallLog = ($PSScriptRoot + '\' + 'RewriteModuleInstallLog.log')

    #Install module
    if ($null -ne $IISRewriteQuery) {
        Write-Verbose "[INFO] IIS URL Rewrite Module 2 already installed on $env:computername"
    } else {
        if ($FullPathToMSI) {
            Write-Verbose "[INFO] Installing IIS URL Rewrite Module 2"
            Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList "/i $($FullPathToMSI.Fullname) /quiet /log $RewriteModuleInstallLog" -Wait
            Start-Sleep -Seconds 15

            $IISRewriteQuery = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9BCA2118-F753-4A1E-BCF3-5A820729965C}' -ErrorAction SilentlyContinue).DisplayName

            if ($null -ne $IISRewriteQuery) {
                Write-Verbose "[OK] IIS URL Rewrite Module 2 installed on $env:computername"
            } else {

                throw "[ERROR] Issue installing IIS URL Rewrite Module 2, please review $($RewriteModuleInstallLog)"
            }
        } else {
            throw "[ERROR] Unable to proceed on $env:computername, path to IIS URL Rewrite Module MSI  not provided and module is not installed."
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


            Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name; patterSyntax = 'Regular Expressions'; stopProcessing = 'False' }
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
            Write-Verbose "[OK] Rewrite rule mitigation removed for $env:COMPUTERNAME :: $website"
        } else {
            Write-Verbose "[INFO] Rewrite rule mitigation does not exist for $env:COMPUTERNAME :: $website"
        }
    }
}
