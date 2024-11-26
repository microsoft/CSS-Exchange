# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Save-DataInfoToFile.ps1
. $PSScriptRoot\Save-RegistryHive.ps1
. $PSScriptRoot\..\Add-ServerNameToFileName.ps1
. $PSScriptRoot\..\Test-CommandExists.ps1
function Save-ServerInfoData {
    Write-Verbose("Function Enter: Save-ServerInfoData")
    $copyTo = $Script:RootCopyToDirectory + "\General_Server_Info"
    New-Item -ItemType Directory -Path $copyTo -Force | Out-Null

    #Get MSInfo from server
    msInfo32.exe /nfo (Add-ServerNameToFileName -FilePath ("{0}\msInfo.nfo" -f $copyTo))
    Write-Host "Waiting for msInfo32.exe process to end before moving on..." -ForegroundColor "Yellow"
    while ((Get-Process | Where-Object { $_.ProcessName -eq "msInfo32" }).ProcessName -eq "msInfo32") {
        Start-Sleep 5
    }

    $tlsRegistrySettingsName = "TLS_RegistrySettings"
    $tlsProtocol = @{
        RegistryPath    = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
        SaveName        = $tlsRegistrySettingsName
        SaveToPath      = $copyTo
        UseGetChildItem = $true
    }
    Save-RegistryHive @tlsProtocol

    $net4Protocol = @{
        RegistryPath = "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        SaveName     = "NET4_$tlsRegistrySettingsName"
        SaveToPath   = $copyTo
    }
    Save-RegistryHive @net4Protocol

    $net4WowProtocol = @{
        RegistryPath = "HKLM:SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        SaveName     = "NET4_Wow_$tlsRegistrySettingsName"
        SaveToPath   = $copyTo
    }
    Save-RegistryHive @net4WowProtocol

    $net2Protocol = @{
        RegistryPath = "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
        SaveName     = "NET2_$tlsRegistrySettingsName"
        SaveToPath   = $copyTo
    }
    Save-RegistryHive @net2Protocol

    $net2WowProtocol = @{
        RegistryPath = "HKLM:SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
        SaveName     = "NET2_Wow_$tlsRegistrySettingsName"
        SaveToPath   = $copyTo
    }
    Save-RegistryHive @net2WowProtocol

    #Running Processes #35
    Save-DataInfoToFile -dataIn (Get-Process) -SaveToLocation ("{0}\Running_Processes" -f $copyTo) -FormatList $false

    #Services Information #36
    Save-DataInfoToFile -dataIn (Get-Service) -SaveToLocation ("{0}\Services_Information" -f $copyTo) -FormatList $false

    #VSSAdmin Information #39
    Save-DataInfoToFile -DataIn (vssadmin list Writers) -SaveToLocation ("{0}\VSS_Writers" -f $copyTo) -SaveXMLFile $false

    #Driver Information #34
    Save-DataInfoToFile -dataIn (Get-ChildItem ("{0}\System32\drivers" -f $env:SystemRoot) | Where-Object { $_.Name -like "*.sys" }) -SaveToLocation ("{0}\System32_Drivers" -f $copyTo)

    Save-DataInfoToFile -DataIn (Get-HotFix | Select-Object Source, Description, HotFixID, InstalledBy, InstalledOn) -SaveToLocation ("{0}\HotFixInfo" -f $copyTo)

    #TCP IP Networking Information #38
    Save-DataInfoToFile -DataIn (ipconfig /all) -SaveToLocation ("{0}\IPConfiguration" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -anob) -SaveToLocation ("{0}\NetStat_ANOB" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (route print) -SaveToLocation ("{0}\Network_Routes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (arp -a) -SaveToLocation ("{0}\Network_ARP" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -naTo) -SaveToLocation ("{0}\Netstat_NATO" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -es) -SaveToLocation ("{0}\Netstat_ES" -f $copyTo) -SaveXMLFile $false

    #IPsec
    Save-DataInfoToFile -DataIn (netsh ipsec dynamic show all) -SaveToLocation ("{0}\IPsec_netsh_dynamic" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netsh ipsec static show all) -SaveToLocation ("{0}\IPsec_netsh_static" -f $copyTo) -SaveXMLFile $false

    #FLTMC
    Save-DataInfoToFile -DataIn (fltmc) -SaveToLocation ("{0}\FLTMC_FilterDrivers" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc volumes) -SaveToLocation ("{0}\FLTMC_Volumes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc instances) -SaveToLocation ("{0}\FLTMC_Instances" -f $copyTo) -SaveXMLFile $false

    Save-DataInfoToFile -DataIn (TaskList /M) -SaveToLocation ("{0}\TaskList_Modules" -f $copyTo) -SaveXMLFile $false

    if (!$Script:localServerObject.Edge) {

        $params = @{
            RegistryPath    = "HKLM:SOFTWARE\Microsoft\Exchange"
            SaveName        = "Exchange_Registry_Hive"
            SaveToPath      = $copyTo
            UseGetChildItem = $true
        }
        Save-RegistryHive @params

        $params = @{
            RegistryPath    = "HKLM:SOFTWARE\Microsoft\ExchangeServer"
            SaveName        = "ExchangeServer_Registry_Hive"
            SaveToPath      = $copyTo
            UseGetChildItem = $true
        }
        Save-RegistryHive @params
    }

    Save-DataInfoToFile -DataIn (gpResult /R /Z) -SaveToLocation ("{0}\GPResult" -f $copyTo) -SaveXMLFile $false
    gpResult /H (Add-ServerNameToFileName -FilePath ("{0}\GPResult.html" -f $copyTo))

    #Storage Information
    if (Test-CommandExists -command "Get-Volume") {
        Save-DataInfoToFile -DataIn (Get-Volume) -SaveToLocation ("{0}\Volume" -f $copyTo)
    } else {
        Write-Verbose("Get-Volume isn't a valid command")
    }

    if (Test-CommandExists -command "Get-Disk") {
        Save-DataInfoToFile -DataIn (Get-Disk) -SaveToLocation ("{0}\Disk" -f $copyTo)
    } else {
        Write-Verbose("Get-Disk isn't a valid command")
    }

    if (Test-CommandExists -command "Get-Partition") {
        Save-DataInfoToFile -DataIn (Get-Partition) -SaveToLocation ("{0}\Partition" -f $copyTo)
    } else {
        Write-Verbose("Get-Partition isn't a valid command")
    }

    if (Test-CommandExists -command "Get-PhysicalDisk") {
        Save-DataInfoToFile -DataIn (Get-PhysicalDisk) -SaveToLocation ("{0}\PhysicalDisk" -f $copyTo)
    } else {
        Write-Verbose("Get-PhysicalDisk isn't a valid command")
    }

    Invoke-ZipFolder -Folder $copyTo
    Write-Verbose("Function Exit: Save-ServerInfoData")
}
