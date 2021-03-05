<#
    BackendCookieMitigation.ps1

    Description:
        This mitigation will filter https requests that contain malicious X-AnonResource-Backend and malformed X-BEResource cookies which were found to be used in the SSRF attacks in the wild.
        This will help with defense against the known patterns observed but not the SSRF as a whole.

    Note:
        The IIS ReWrite rules will be removed after Exchange is upgraded and the mitigation will need to be reapplied.

    Impact:
        No known impact to Exchange functionality, however, limited testing has been performed

    Requirements:
        URL Rewrite : The Official Microsoft IIS Site MSI (https://www.iis.net/downloads/microsoft/url-rewrite)


    Examples:

    To apply with MSI install via PowerShell:
        .\BackendCookieMitigation.ps1 -FullPathToMSI “<FullPathToMSI>" -WebSiteNames "Default Web Site" -Verbose

    To apply without MSI install via PowerShell:
        .\BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -Verbose

    To rollback:
        .\BackendCookieMitigation.ps1 -WebSiteNames "Default Web Site" -RollbackMitigation -Verbose
#>

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
    Write-Verbose "[INFO] Starting mitigation process on $env:computername"

    #Check if IIS URL Rewrite Module 2 is installed
    Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername"
    $IISRewriteQuery = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9BCA2118-F753-4A1E-BCF3-5A820729965C}' -ErrorAction SilentlyContinue).DisplayName

    $RewriteModuleInstallLog = ($FullPathToMSI.Directory.FullName + '\' + 'RewriteModuleInstallLog.log')

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
