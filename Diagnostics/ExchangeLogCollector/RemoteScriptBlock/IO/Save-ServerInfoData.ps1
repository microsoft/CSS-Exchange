# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Save-DataInfoToFile.ps1
. $PSScriptRoot\..\Add-ServerNameToFileName.ps1
. $PSScriptRoot\..\Test-CommandExists.ps1
Function Save-ServerInfoData {
    Write-Verbose("Function Enter: Save-ServerInfoData")
    $copyTo = $Script:RootCopyToDirectory + "\General_Server_Info"
    New-Item -ItemType Directory -Path $copyTo -Force | Out-Null

    #Get MSInfo from server
    msinfo32.exe /nfo (Add-ServerNameToFileName -FilePath ("{0}\msinfo.nfo" -f $copyTo))
    Write-Host "Waiting for msinfo32.exe process to end before moving on..." -ForegroundColor "Yellow"
    while ((Get-Process | Where-Object { $_.ProcessName -eq "msinfo32" }).ProcessName -eq "msinfo32") {
        Start-Sleep 5;
    }

    #Include TLS Registry Information #84
    $tlsSettings = @()
    try {
        $tlsSettings += Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Recurse | Where-Object { $_.Name -like "*TLS*" } -ErrorAction stop
    } catch {
        Write-Verbose("Failed to get child items of 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'")
        Invoke-CatchBlockActions
    }
    try {
        $regBaseV4 = "HKLM:SOFTWARE\{0}\.NETFramework\v4.0.30319"
        $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Microsoft") -ErrorAction stop
        $tlsSettings += Get-Item ($currentKey = $regBaseV4 -f "Wow6432Node\Microsoft") -ErrorAction stop
    } catch {
        Write-Verbose("Failed to get child items of '{0}'" -f $currentKey)
        Invoke-CatchBlockActions
    }
    try {
        $regBaseV2 = "HKLM:SOFTWARE\{0}\.NETFramework\v2.0.50727"
        $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Microsoft") -ErrorAction stop
        $tlsSettings += Get-Item ($currentKey = $regBaseV2 -f "Wow6432Node\Microsoft") -ErrorAction stop
    } catch {
        Write-Verbose("Failed to get child items of '{0}'" -f $currentKey)
        Invoke-CatchBlockActions
    }
    Save-DataInfoToFile -DataIn $tlsSettings -SaveToLocation ("{0}\TLS_RegistrySettings" -f $copyTo) -FormatList $false

    #Running Processes #35
    Save-DataInfoToFile -dataIn (Get-Process) -SaveToLocation ("{0}\Running_Processes" -f $copyTo) -FormatList $false

    #Services Information #36
    Save-DataInfoToFile -dataIn (Get-Service) -SaveToLocation ("{0}\Services_Information" -f $copyTo) -FormatList $false

    #VSSAdmin Information #39
    Save-DataInfoToFile -DataIn (vssadmin list Writers) -SaveToLocation ("{0}\VSS_Writers" -f $copyTo) -SaveXMLFile $false

    #Driver Information #34
    Save-DataInfoToFile -dataIn (Get-ChildItem ("{0}\System32\drivers" -f $env:SystemRoot) | Where-Object { $_.Name -like "*.sys" }) -SaveToLocation ("{0}\System32_Drivers" -f $copyTo)

    Save-DataInfoToFile -DataIn (Get-HotFix | Select-Object Source, Description, HotFixID, InstalledBy, InstalledOn) -SaveToLocation ("{0}\HotFixInfo" -f $copyTo)

    #TCPIP Networking Information #38
    Save-DataInfoToFile -DataIn (ipconfig /all) -SaveToLocation ("{0}\IPConfiguration" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -anob) -SaveToLocation ("{0}\NetStat_ANOB" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (route print) -SaveToLocation ("{0}\Network_Routes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (arp -a) -SaveToLocation ("{0}\Network_ARP" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -nato) -SaveToLocation ("{0}\Netstat_NATO" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netstat -es) -SaveToLocation ("{0}\Netstat_ES" -f $copyTo) -SaveXMLFile $false

    #IPsec
    Save-DataInfoToFile -DataIn (netsh ipsec dynamic show all) -SaveToLocation ("{0}\IPsec_netsh_dynamic" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (netsh ipsec static show all) -SaveToLocation ("{0}\IPsec_netsh_static" -f $copyTo) -SaveXMLFile $false

    #FLTMC
    Save-DataInfoToFile -DataIn (fltmc) -SaveToLocation ("{0}\FLTMC_FilterDrivers" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc volumes) -SaveToLocation ("{0}\FLTMC_Volumes" -f $copyTo) -SaveXMLFile $false
    Save-DataInfoToFile -DataIn (fltmc instances) -SaveToLocation ("{0}\FLTMC_Instances" -f $copyTo) -SaveXMLFile $false

    Save-DataInfoToFile -DataIn (TASKLIST /M) -SaveToLocation ("{0}\TaskList_Modules" -f $copyTo) -SaveXMLFile $false

    if (!$Script:localServerObject.Edge) {
        $hiveKey = @()
        try {
            $hiveKey = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Exchange\ -Recurse -ErrorAction Stop
        } catch {
            Write-Verbose("Failed to get child item on HKLM:\SOFTWARE\Microsoft\Exchange\")
            Invoke-CatchBlockActions
        }
        $hiveKey += Get-ChildItem HKLM:\SOFTWARE\Microsoft\ExchangeServer\ -Recurse
        Save-DataInfoToFile -DataIn $hiveKey -SaveToLocation ("{0}\Exchange_Registry_Hive" -f $copyTo) -SaveTextFile $false
    }

    Save-DataInfoToFile -DataIn (gpresult /R /Z) -SaveToLocation ("{0}\GPResult" -f $copyTo) -SaveXMLFile $false
    gpresult /H (Add-ServerNameToFileName -FilePath ("{0}\GPResult.html" -f $copyTo))

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

    Invoke-ZipFolder -Folder $copyTo
    Write-Verbose("Function Exit: Save-ServerInfoData")
}
