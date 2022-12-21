# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeDependentServices {
    [CmdletBinding()]
    param(
        [string]$MachineName
    )
    begin {

        function NewServiceObject {
            param(
                [object]$Service
            )
            $name = $Service.Name
            $status = "Unknown"
            $startType = "Unknown"
            try {
                $status = $Service.Status.ToString()
            } catch {
                Write-Verbose "Failed to set Status of service '$name'"
                Invoke-CatchActions
            }
            try {
                $startType = $Service.StartType.ToString()
            } catch {
                Write-Verbose "Failed to set Start Type of service '$name'"
                Invoke-CatchActions
            }
            return [PSCustomObject]@{
                Name      = $name
                Status    = $status
                StartType = $startType
            }
        }

        function NewMonitorServiceObject {
            param(
                [Parameter(Mandatory = $true, Position = 1)]
                [string]$ServiceName,
                [Parameter(Mandatory = $false)]
                [ValidateSet("Automatic", "Manual")]
                [string]$StartType = "Automatic",
                [Parameter(Mandatory = $false)]
                [ValidateSet("Common", "Critical")]
                [string]$Type = "Critical"
            )
            return [PSCustomObject]@{
                ServiceName = $ServiceName
                StartType   = $StartType
                Type        = $Type
            }
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $servicesList = @(
            (NewMonitorServiceObject "WinMgmt"),
            (NewMonitorServiceObject "W3Svc"),
            (NewMonitorServiceObject "IISAdmin"),
            (NewMonitorServiceObject "Pla" -StartType "Manual"),
            (NewMonitorServiceObject "MpsSvc"),
            (NewMonitorServiceObject "RpcEptMapper"),
            (NewMonitorServiceObject "EventLog"),
            (NewMonitorServiceObject "MSExchangeADTopology"),
            (NewMonitorServiceObject "MSExchangeDelivery"),
            (NewMonitorServiceObject "MSExchangeFastSearch"),
            (NewMonitorServiceObject "MSExchangeFrontEndTransport"),
            (NewMonitorServiceObject "MSExchangeIS"),
            (NewMonitorServiceObject "MSExchangeRepl"),
            (NewMonitorServiceObject "MSExchangeRPC"),
            (NewMonitorServiceObject "MSExchangeServiceHost"),
            (NewMonitorServiceObject "MSExchangeSubmission"),
            (NewMonitorServiceObject "MSExchangeTransport"),
            (NewMonitorServiceObject "HostControllerService"),
            (NewMonitorServiceObject "MSExchangeAntispamUpdate" -Type "Common"),
            (NewMonitorServiceObject "MSComplianceAudit" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeCompliance" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeDagMgmt" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeDiagnostics" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeEdgeSync" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeHM" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeHMRecovery" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeMailboxAssistants" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeMailboxReplication" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeMitigation" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeThrottling" -Type "Common"),
            (NewMonitorServiceObject "MSExchangeTransportLogSearch" -Type "Common"),
            (NewMonitorServiceObject "BITS" -Type "Common" -StartType "Manual") # BITS have seen both Manual and Automatic
        )
        $notRunningCriticalServices = New-Object 'System.Collections.Generic.List[object]'
        $notRunningCommonServices = New-Object 'System.Collections.Generic.List[object]'
        $misconfiguredServices = New-Object 'System.Collections.Generic.List[object]'
        $getServicesList = New-Object 'System.Collections.Generic.List[object]'
        $monitorServicesList = New-Object 'System.Collections.Generic.List[object]'
    } process {
        try {
            $getServices = Get-Service -ComputerName $MachineName -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to get the services on the server"
            Invoke-CatchActions
            return
        }

        foreach ($service in $getServices) {

            $monitor = $servicesList | Where-Object { $_.ServiceName -eq $service.Name }

            if ($null -ne $monitor) {
                # Any critical services not running, add to list
                # Any critical or common services not set to Automatic that should be or set to disabled, add to list
                # Any common services not running, besides the ones that are set to manual, add to list
                Write-Verbose "Working on $($monitor.ServiceName)"
                $monitorServicesList.Add((NewServiceObject $service))

                if (-not ($service.Status.ToString() -eq "Running" -or
                ($monitor.Type -eq "Common" -and
                        $monitor.StartType -eq "Manual"))) {
                    if ($monitor.Type -eq "Critical") {
                        $notRunningCriticalServices.Add((NewServiceObject $service))
                    } else {
                        $notRunningCommonServices.Add((NewServiceObject $service))
                    }
                }
                try {
                    $startType = $service.StartType.ToString()
                    Write-Verbose "StartType set to $startType"

                    if ($startType -ne "Automatic") {
                        if ($monitor.StartType -eq "Manual" -and
                            $startType -eq "Manual") {
                            Write-Verbose "Good configuration"
                        } else {
                            $serviceObject = NewServiceObject $service
                            $serviceObject | Add-Member -MemberType NoteProperty -Name "CorrectStartType" -Value $monitor.StartType
                            $misconfiguredServices.Add($serviceObject)
                        }
                    }
                } catch {
                    Write-Verbose "Failed to convert StartType"
                    Invoke-CatchActions
                }
            }
            $getServicesList.Add((NewServiceObject $service))
        }
    } end {
        return [PSCustomObject]@{
            Services      = $getServicesList
            Monitor       = $monitorServicesList
            Misconfigured = $misconfiguredServices
            Critical      = $notRunningCriticalServices
            Common        = $notRunningCommonServices
        }
    }
}
