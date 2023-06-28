# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IISWebSite {
    param(
        [array]$WebSitesToProcess
    )

    $returnList = New-Object 'System.Collections.Generic.List[object]'
    $webSites = New-Object 'System.Collections.Generic.List[object]'

    if ($null -eq $WebSitesToProcess) {
        $webSites.AddRange((Get-WebSite))
    } else {
        foreach ($iisWebSite in $WebSitesToProcess) {
            $webSites.Add((Get-WebSite -Name $($iisWebSite)))
        }
    }

    $bindings = Get-WebBinding

    foreach ($site in $webSites) {
        Write-Verbose "Working on Site: $($site.Name)"
        $siteBindings = $bindings |
            Where-Object { $_.ItemXPath -like "*@name='$($site.name)' and @id='$($site.id)'*" }
        # Logic should be consistent for all ways we call Get-WebConfigFile
        try {
            $configurationFilePath = (Get-WebConfigFile "IIS:\Sites\$($site.Name)").FullName
        } catch {
            $finder = "\\?\"
            if (($_.Exception.ErrorCode -eq -2147024846 -or
                    $_.Exception.ErrorCode -eq -2147024883) -and
                $_.Exception.Message.Contains($finder)) {
                $message = $_.Exception.Message
                $index = $message.IndexOf($finder) + $finder.Length
                $configurationFilePath = $message.Substring($index, ($message.IndexOf([System.Environment]::NewLine) - $index)).Trim()
                Write-Verbose "Found possible file path from exception: $configurationFilePath"
            } else {
                Write-Verbose "Unable to find possible file path based off exception: $($_.Exception)"
            }
        }

        $webConfigExists = Test-Path $configurationFilePath
        $webConfigContent = $null
        $validWebConfig = $false

        if ($webConfigExists) {
            $webConfigContent = (Get-Content $configurationFilePath -Raw).Trim()

            try {
                [xml]$webConfigContent | Out-Null
                $validWebConfig = $true
            } catch {
                # Inside of Invoke-Command, can't use Invoke-CatchActions
                Write-Verbose "Failed to convert IIS web config '$configurationFilePath' to xml. Exception: $($_.Exception)"
            }
        }

        $returnList.Add([PSCustomObject]@{
                Name                       = $site.Name
                Id                         = $site.Id
                State                      = $site.State
                Bindings                   = $siteBindings
                Limits                     = $site.Limits
                LogFile                    = $site.logFile
                TraceFailedRequestsLogging = $site.traceFailedRequestsLogging
                Hsts                       = $site.hsts
                ApplicationDefaults        = $site.applicationDefaults
                VirtualDirectoryDefaults   = $site.virtualDirectoryDefaults
                Collection                 = $site.collection
                ApplicationPool            = $site.applicationPool
                EnabledProtocols           = $site.enabledProtocols
                PhysicalPath               = $site.physicalPath.Replace("%windir%", $env:windir).Replace("%SystemDrive%", $env:SystemDrive)
                ConfigurationFileInfo      = [PSCustomObject]@{
                    Location = $configurationFilePath
                    Content  = $webConfigContent
                    Exist    = $webConfigExists
                    Valid    = $validWebConfig
                }
            }
        )
    }
    return $returnList
}
