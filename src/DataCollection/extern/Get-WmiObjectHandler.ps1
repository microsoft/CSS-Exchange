#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Get-WmiObjectHandler/Get-WmiObjectHandler.ps1
#v21.01.22.2234
Function Get-WmiObjectHandler {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'This is what this function is for')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $true)][string]$Class,
        [Parameter(Mandatory = $false)][string]$Filter,
        [Parameter(Mandatory = $false)][string]$Namespace,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-WmiObjectHandler")
    Write-VerboseWriter("Passed: [string]ComputerName: {0} | [string]Class: {1} | [string]Filter: {2} | [string]Namespace: {3}" -f $ComputerName, $Class, $Filter, $Namespace)
    $execute = @{
        ComputerName = $ComputerName
        Class        = $Class
    }
    if (![string]::IsNullOrEmpty($Filter)) {
        $execute.Add("Filter", $Filter)
    }
    if (![string]::IsNullOrEmpty($Namespace)) {
        $execute.Add("Namespace", $Namespace)
    }
    try {
        $wmi = Get-WmiObject @execute -ErrorAction Stop
        return $wmi
    } catch {
        Write-VerboseWriter("Failed to run Get-WmiObject object on class '{0}'" -f $Class)
        if ($null -ne $CatchActionFunction) {
            & $CatchActionFunction
        }
    }
}
