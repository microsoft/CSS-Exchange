# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ComputerCoresObject {
    param(
        [Parameter(Mandatory = $true)][string]$Machine_Name
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand) Passed: $Machine_Name"

    $returnObj = New-Object PSCustomObject
    $returnObj | Add-Member -MemberType NoteProperty -Name Error -Value $false
    $returnObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Machine_Name
    $returnObj | Add-Member -MemberType NoteProperty -Name NumberOfCores -Value ([int]::empty)
    $returnObj | Add-Member -MemberType NoteProperty -Name Exception -Value ([string]::empty)
    $returnObj | Add-Member -MemberType NoteProperty -Name ExceptionType -Value ([string]::empty)

    try {
        $wmi_obj_processor = Get-WmiObjectHandler -ComputerName $Machine_Name -Class "Win32_Processor" -CatchActionFunction ${Function:Invoke-CatchActions}

        foreach ($processor in $wmi_obj_processor) {
            $returnObj.NumberOfCores += $processor.NumberOfCores
        }

        Write-Grey("Server {0} Cores: {1}" -f $Machine_Name, $returnObj.NumberOfCores)
    } catch {
        Invoke-CatchActions
        $thisError = $Error[0]

        if ($thisError.Exception.Gettype().FullName -eq "System.UnauthorizedAccessException") {
            Write-Yellow("Unable to get processor information from server {0}. You do not have the correct permissions to get this data from that server. Exception: {1}" -f $Machine_Name, $thisError.ToString())
        } else {
            Write-Yellow("Unable to get processor information from server {0}. Reason: {1}" -f $Machine_Name, $thisError.ToString())
        }
        $returnObj.Exception = $thisError.ToString()
        $returnObj.ExceptionType = $thisError.Exception.Gettype().FullName
        $returnObj.Error = $true
    }

    return $returnObj
}

Function Get-ExchangeDCCoreRatio {

    Invoke-ScriptLogFileLocation -FileName "HealthChecker-ExchangeDCCoreRatio"
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Grey("Exchange Server Health Checker Report - AD GC Core to Exchange Server Core Ratio - v{0}" -f $BuildVersion)
    $coreRatioObj = New-Object PSCustomObject

    try {
        Write-Verbose "Attempting to load Active Directory Module"
        Import-Module ActiveDirectory
        Write-Verbose "Successfully loaded"
    } catch {
        Write-Red("Failed to load Active Directory Module. Stopping the script")
        exit
    }

    $ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
    [array]$DomainControllers = (Get-ADForest).Domains |
        ForEach-Object { Get-ADDomainController -Server $_ } |
        Where-Object { $_.IsGlobalCatalog -eq $true -and $_.Site -eq $ADSite }

    [System.Collections.Generic.List[System.Object]]$DCList = New-Object System.Collections.Generic.List[System.Object]
    $DCCoresTotal = 0
    Write-Break
    Write-Grey("Collecting data for the Active Directory Environment in Site: {0}" -f $ADSite)
    $iFailedDCs = 0

    foreach ($DC in $DomainControllers) {
        $DCCoreObj = Get-ComputerCoresObject -Machine_Name $DC.Name
        $DCList.Add($DCCoreObj)

        if (-not ($DCCoreObj.Error)) {
            $DCCoresTotal += $DCCoreObj.NumberOfCores
        } else {
            $iFailedDCs++
        }
    }

    $coreRatioObj | Add-Member -MemberType NoteProperty -Name DCList -Value $DCList

    if ($iFailedDCs -eq $DomainControllers.count) {
        #Core count is going to be 0, no point to continue the script
        Write-Red("Failed to collect data from your DC servers in site {0}." -f $ADSite)
        Write-Yellow("Because we can't determine the ratio, we are going to stop the script. Verify with the above errors as to why we failed to collect the data and address the issue, then run the script again.")
        exit
    }

    [array]$ExchangeServers = Get-ExchangeServer | Where-Object { $_.Site -match $ADSite }
    $EXCoresTotal = 0
    [System.Collections.Generic.List[System.Object]]$EXList = New-Object System.Collections.Generic.List[System.Object]
    Write-Break
    Write-Grey("Collecting data for the Exchange Environment in Site: {0}" -f $ADSite)
    foreach ($svr in $ExchangeServers) {
        $EXCoreObj = Get-ComputerCoresObject -Machine_Name $svr.Name
        $EXList.Add($EXCoreObj)

        if (-not ($EXCoreObj.Error)) {
            $EXCoresTotal += $EXCoreObj.NumberOfCores
        }
    }
    $coreRatioObj | Add-Member -MemberType NoteProperty -Name ExList -Value $EXList

    Write-Break
    $CoreRatio = $EXCoresTotal / $DCCoresTotal
    Write-Grey("Total DC/GC Cores: {0}" -f $DCCoresTotal)
    Write-Grey("Total Exchange Cores: {0}" -f $EXCoresTotal)
    Write-Grey("You have {0} Exchange Cores for every Domain Controller Global Catalog Server Core" -f $CoreRatio)

    if ($CoreRatio -gt 8) {
        Write-Break
        Write-Red("Your Exchange to Active Directory Global Catalog server's core ratio does not meet the recommended guidelines of 8:1")
        Write-Red("Recommended guidelines for Exchange 2013/2016 for every 8 Exchange cores you want at least 1 Active Directory Global Catalog Core.")
        Write-Yellow("Documentation:")
        Write-Yellow("`thttps://aka.ms/HC-PerfSize")
        Write-Yellow("`thttps://aka.ms/HC-ADCoreCount")
    } else {
        Write-Break
        Write-Green("Your Exchange Environment meets the recommended core ratio of 8:1 guidelines.")
    }

    $XMLDirectoryPath = $OutputFullPath.Replace(".txt", ".xml")
    $coreRatioObj | Export-Clixml $XMLDirectoryPath
    Write-Grey("Output file written to {0}" -f $OutputFullPath)
    Write-Grey("Output XML Object file written to {0}" -f $XMLDirectoryPath)
}
