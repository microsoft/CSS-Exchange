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

        To rollback - Note: This does not uninstall the IIS Rewrite module, only the rules.

    .LINK
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://www.microsoft.com/en-us/download/details.aspx?id=5747
        https://www.microsoft.com/en-us/download/details.aspx?id=7435

#>

[CmdLetBinding()]
param(
    [System.IO.FileInfo]$FullPathToMSI,
    [ValidateNotNullOrEmpty()]
    [string[]]$WebSiteNames,
    [switch]$RollbackMitigation
)
function GetMsiProductVersion {
    param (
        [System.IO.FileInfo]$filename
    )

    try {
        $windowsInstaller = New-Object -com WindowsInstaller.Installer

        $database = $windowsInstaller.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $Null,
            $windowsInstaller, @($filename.FullName, 0)
        )

        $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $View = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $Null, $database, ($q)
        )

        $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)

        $record = $View.GetType().InvokeMember(
            "Fetch", "InvokeMethod", $Null, $View, $Null
        )

        $productVersion = $record.GetType().InvokeMember(
            "StringData", "GetProperty", $Null, $record, 1
        )

        $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null)

        return $productVersion
    } catch {
        throw "Failed to get MSI file version the error was: {0}." -f $_
    }
}
function Get-InstalledSoftware {
    <#
        .SYNOPSIS
            Retrieves a list of all software installed on a Windows computer.
        .EXAMPLE
            PS> Get-InstalledSoftware

            This example retrieves all software installed on the local computer.
        .PARAMETER ComputerName
            If querying a remote computer, use the computer name here.

        .PARAMETER Name
            The software title you'd like to limit the query to.

        .PARAMETER Guid
            The software GUID you'e like to limit the query to
        #>
    [CmdletBinding()]
    param (

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [guid]$Guid
    )
    process {
        try {
            $scriptBlock = {
                $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }

                $UninstallKeys = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
                $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                    "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                }
                if (-not $UninstallKeys) {
                    Write-Warning -Message 'No software registry keys found'
                } else {
                    foreach ($UninstallKey in $UninstallKeys) {
                        $friendlyNames = @{
                            'DisplayName'    = 'Name'
                            'DisplayVersion' = 'Version'
                        }
                        Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
                        if ($Name) {
                            $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
                        } elseif ($GUID) {
                            $WhereBlock = { $_.PsChildName -eq $Guid.Guid }
                        } else {
                            $WhereBlock = { $_.GetValue('DisplayName') }
                        }
                        $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
                        if (-not $SwKeys) {
                            Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
                        } else {
                            foreach ($SwKey in $SwKeys) {
                                $output = @{ }
                                foreach ($ValName in $SwKey.GetValueNames()) {
                                    if ($ValName -ne 'Version') {
                                        $output.InstallLocation = ''
                                        if ($ValName -eq 'InstallLocation' -and
                                            ($SwKey.GetValue($ValName)) -and
                                            (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                                            $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                                        }
                                        [string]$ValData = $SwKey.GetValue($ValName)
                                        if ($friendlyNames[$ValName]) {
                                            $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                                        } else {
                                            $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                                        }
                                    }
                                }
                                $output.GUID = ''
                                if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                                    $output.GUID = $SwKey.PSChildName
                                }
                                New-Object -TypeName PSObject -Prop $output
                            }
                        }
                    }
                }
            }

            if ($ComputerName -eq $env:COMPUTERNAME) {
                & $scriptBlock $PSBoundParameters
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
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

if (!$RollbackMitigation) {
    Write-Verbose "[INFO] Starting mitigation process on $env:computername"

    #Check if IIS URL Rewrite Module 2 is installed
    Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername"

    #If IIS 10 check for URL rewrite 2.1 else URL rewrite 2.0
    $RewriteModule = Get-InstalledSoftware | Where-Object { $_.Name -like "*IIS*" -and $_.Name -like "*URL*" -and $_.Name -like "*2*" }
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

        Write-Verbose "[INFO] IIS URL Rewrite Module 2 already installed on $env:computername"
    } else {

        if ($FullPathToMSI) {

            $MSIProductVersion = GetMsiProductVersion -filename $FullPathToMSI

            #If IIS 10 assert URL rewrite 2.1 else URL rewrite 2.0
            if ($IISVersion.VersionString -like "*10.*" -and $MSIProductVersion -eq "7.2.2") {
                throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.1"
            }
            if ($IISVersion.VersionString -notlike "*10.*" -and $MSIProductVersion -eq "7.2.1993") {
                throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.0"
            }

            Write-Verbose "[INFO] Installing IIS URL Rewrite Module 2"
            $arguments = " /i " + '"' + $FullPathToMSI.FullName + '"' + " /quiet /log " + '"' + $RewriteModuleInstallLog + '"'
            $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"
            Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
            Start-Sleep -Seconds 15
            $RewriteModule = Get-InstalledSoftware | Where-Object { $_.Name -like "*IIS*" -and $_.Name -like "*URL*" -and $_.Name -like "*2*" }
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
