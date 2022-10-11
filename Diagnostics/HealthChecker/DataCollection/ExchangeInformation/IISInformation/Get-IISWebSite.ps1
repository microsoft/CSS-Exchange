# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IISWebSite {
    $webSites = Get-WebSite
    $bindings = Get-WebBinding
    $returnList = New-Object 'System.Collections.Generic.List[object]'

    foreach ($site in $webSites) {
        $siteBindings = $bindings |
            Where-Object { $_.ItemXPath -like "*@name='$($site.name)' and @id='$($site.id)'*" }
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
            }
        )
    }
    return $returnList
}
