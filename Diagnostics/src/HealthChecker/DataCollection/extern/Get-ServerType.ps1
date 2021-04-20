#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-ServerType/Get-ServerType.ps1
#v21.01.22.2234
Function Get-ServerType {
    [CmdletBinding()]
    [OutputType("System.String")]
    param(
        [Parameter(Mandatory = $true)][string]$ServerType
    )
    #Function Version #v21.01.22.2234

    Write-VerboseWriter("Calling: Get-ServerType")
    $returnServerType = [string]::Empty
    if ($ServerType -like "VMware*") { $returnServerType = "VMware" }
    elseif ($ServerType -like "*Amazon EC2*") { $returnServerType = "AmazonEC2" }
    elseif ($ServerType -like "*Microsoft Corporation*") { $returnServerType = "HyperV" }
    elseif ($ServerType.Length -gt 0) { $returnServerType = "Physical" }
    else { $returnServerType = "Unknown" }

    Write-VerboseWriter("Returning: {0}" -f $returnServerType)
    return $returnServerType
}
