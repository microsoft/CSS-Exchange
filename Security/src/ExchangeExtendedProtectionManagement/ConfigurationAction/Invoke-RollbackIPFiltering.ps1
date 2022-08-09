# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\Write-ErrorInformation.ps1

$RollbackIPFiltering = {
    param(
        [Object]$Arguments
    )

    $Site = $Arguments.Site
    $VDir = $Arguments.VDir
    $Filter = 'system.webServer/security/ipSecurity'
    $IISPath = 'IIS:\'

    $SiteVDirLocation = $Site
    if ($VDir -ne '') {
        $SiteVDirLocation += '/' + $VDir
    }

    $results = @{
        BackUpPath              = $null
        BackupCurrentSuccessful = $false
        RestorePath             = $null
        RestoreSuccessful       = $false
        ErrorContext            = $null
    }

    function Backup-currentIpFilteringRules {
        param(
            $BackupPath
        )

        $Filter = 'system.webServer/security/ipSecurity'
        $IISPath = 'IIS:\'

        $ExistingRules = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection
        $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
        if ($null -eq $ExistingRules -or $ExistingRules.Length -eq 0) {
            $BackupFilteringConfiguration = @{DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
        } else {
            $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
        }

        $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath

        return $true
    }

    function Restore-OriginalIpFilteringRules {
        param(
            $OriginalIpFilteringRules,
            $DefaultForUnspecifiedIPs
        )

        Clear-WebConfiguration -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -ErrorAction Stop
        $RulesToBeAdded = @()
        foreach ($IpFilteringRule in $OriginalIpFilteringRules) {
            $RulesToBeAdded += @{ipAddress=$IpFilteringRule.ipAddress; subnetMask=$IpFilteringRule.subnetMask; domainName=$IpFilteringRule.domainName; allowed=$IpFilteringRule.allowed; }
        }
        Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $DefaultForUnspecifiedIPs.Value
        Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop

        return $true
    }

    try {
        $results.BackUpPath = "$($env:WINDIR)\System32\inetsrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/','-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"
        $results.BackupCurrentSuccessful = Backup-currentIpFilteringRules -BackupPath $results.BackUpPath

        $results.RestorePath = (Get-ChildItem "$($env:WINDIR)\System32\inetsrv\config\" -Filter ("*IpFilteringRules_"+  $SiteVDirLocation.Replace('/','-') + "*.bak") | Sort-Object CreationTime | Select-Object -First 1).FullName
        $originalIpFilteringConfigurations = (Get-Content $results.RestorePath | Out-String | ConvertFrom-Json)
        $results.RestoreSuccessful = Restore-OriginalIpFilteringRules -OriginalIpFilteringRules ($originalIpFilteringConfigurations.Rules) -DefaultForUnspecifiedIPs ($originalIpFilteringConfigurations.DefaultForUnspecifiedIPs)
    } catch {
        $results.ErrorContext = $_
    }

    return $results
}

function Invoke-RollbackIPFiltering {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,
        [Parameter(Mandatory = $true)]
        [string]$Site,
        [Parameter(Mandatory = $true)]
        [string]$VDir
    )

    begin {
        $FailedServers = New-Object 'System.Collections.Generic.List[string]'

        $progressParams = @{
            Activity        = "Rolling back IP filtering Rules"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        $scriptblockArgs = [PSCustomObject]@{
            Site = $Site
            VDir = $VDir
        }

        $exchangeServersProcessed = 0
        $totalExchangeServers = $ExchangeServers.Count
        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -" # Should this be at the start as the server is already processed?
            $progressParams.PercentComplete = ($exchangeServersProcessed / $totalExchangeServers * 100)
            $progressParams.Status = "$baseStatus Rolling back rules"
            Write-Progress @progressParams
            $exchangeServersProcessed++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with Arguments Site: {1}, VDir: {2}" -f $Server.Name, $Site, $VDir)
            Write-Host ("Restoring previous state for Server {0}" -f $Server.Name)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server.Name -ScriptBlock $RollbackIPFiltering -ArgumentList $scriptblockArgs
            $Failed = $false

            if ($resultsInvoke.BackupCurrentSuccessful) {
                Write-Verbose "Successfully backed up current configuration on server $($Server.Name) at $($resultsInvoke.BackUpPath)"
                if ($resultsInvoke.RestoreSuccessful) {
                    Write-Host "Successfully rolled back ip filtering rules on server $($Server.Name) from $($resultsInvoke.RestorePath)" -ForegroundColor Green
                } else {
                    Write-Host "Failed to rollback ip filtering rules on server $($Server.Name). Aborting rollback on the server $($Server.Name). Inner Exception:" -ForegroundColor Red
                    Write-HostErrorInformation $resultsInvoke.ErrorContext
                    $Failed = $true
                }
            } else {
                Write-Host "Failed to backup the current configuration on server $($Server.Name). Aborting rollback on the server $($Server.Name). Inner Exception:" -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $Failed = $true
            }

            if ($Failed) {
                $FailedServers += $Server.Name
            }
        }
    } end {
        if ($FailedServers.Length -gt 0) {
            Write-Host ("Unable to rollback for the following servers: {0}" -f [string]::Join(", ", $FailedServers)) -ForegroundColor Red
        }
    }
}
