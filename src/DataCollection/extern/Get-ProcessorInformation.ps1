#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-ProcessorInformation/Get-ProcessorInformation.ps1
#v21.01.22.2234
Function Get-ProcessorInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MachineName,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-ProcessorInformation")
    $wmiObject = Get-WmiObjectHandler -ComputerName $MachineName -Class "Win32_Processor" -CatchActionFunction $CatchActionFunction
    Write-VerboseWriter("Processor object type: {0}" -f ($wmiObjectType = $wmiObject.GetType().Name))

    if ($wmiObjectType -eq "ManagementObject") {
        $processorName = $wmiObject.Name
        $maxClockSpeed = $wmiObject.MaxClockSpeed
    } else {
        $processorName = $wmiObject[0].Name
        $maxClockSpeed = $wmiObject[0].MaxClockSpeed
    }

    Write-VerboseWriter("Getting the total number of cores in the processor(s)")
    $processorIsThrottled = $false
    $currentClockSpeed = 0
    $previousProcessor = $null
    $differentProcessorsDetected = $false
    $differentProcessorCoreCountDetected = $false
    foreach ($processor in $wmiObject) {
        $numberOfPhysicalCores += $processor.NumberOfCores
        $numberOfLogicalCores += $processor.NumberOfLogicalProcessors
        $numberOfProcessors++

        if ($processor.CurrentClockSpeed -lt $processor.MaxClockSpeed) {
            Write-VerboseWriter("Processor is being throttled")
            $processorIsThrottled = $true
            $currentClockSpeed = $processor.CurrentClockSpeed
        }
        if ($null -ne $previousProcessor) {
            if ($processor.Name -ne $previousProcessor.Name -or
                $processor.MaxClockSpeed -ne $previousProcessor.MaxMegacyclesPerCore) {
                Write-VerboseWriter("Different Processors are detected!!! This is an issue.")
                $differentProcessorsDetected = $true
            }
            if ($processor.NumberOfLogicalProcessors -ne $previousProcessor.NumberOfLogicalProcessors) {
                Write-VerboseWriter("Different Processor core count per processor socket detected. This is an issue.")
                $differentProcessorCoreCountDetected = $true
            }
        }
        $previousProcessor = $processor
    }
    Write-VerboseWriter("NumberOfPhysicalCores: {0} | NumberOfLogicalCores: {1} | NumberOfProcessors: {2} | ProcessorIsThrottled: {3} | CurrentClockSpeed: {4} | DifferentProcessorsDetected: {5} | DifferentProcessorCoreCountDetected: {6}" -f $numberOfPhysicalCores,
        $numberOfLogicalCores, $numberOfProcessors, $processorIsThrottled, $currentClockSpeed, $differentProcessorsDetected, $differentProcessorCoreCountDetected)

    $presentedProcessorCoreCount = Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock { [System.Environment]::ProcessorCount } -ScriptBlockDescription "Trying to get the System.Environment ProcessorCount" -CatchActionFunction $CatchActionFunction
    if ($null -eq $presentedProcessorCoreCount) {
        Write-VerboseWriter("Wasn't able to get Presented Processor Core Count on the Server. Setting to -1.")
        $presentedProcessorCoreCount = -1
    } else {
        Write-VerboseWriter("Presented Processor Core Count: {0}" -f $presentedProcessorCoreCount)
    }

    $processorInformationObject = New-Object PSCustomObject
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $processorName
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "MaxMegacyclesPerCore" -Value $maxClockSpeed
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfPhysicalCores" -Value $numberOfPhysicalCores
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfLogicalCores" -Value $numberOfLogicalCores
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "NumberOfProcessors" -Value $numberOfProcessors
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "CurrentMegacyclesPerCore" -Value $currentClockSpeed
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "ProcessorIsThrottled" -Value $processorIsThrottled
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "DifferentProcessorsDetected" -Value $differentProcessorsDetected
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "DifferentProcessorCoreCountDetected" -Value $differentProcessorCoreCountDetected
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "EnvironmentProcessorCount" -Value $presentedProcessorCoreCount
    $processorInformationObject | Add-Member -MemberType NoteProperty -Name "ProcessorClassObject" -Value $wmiObject

    Write-VerboseWriter("Exiting: Get-ProcessorInformation")
    return $processorInformationObject
}
