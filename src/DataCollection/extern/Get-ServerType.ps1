#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerType/Get-ServerType.ps1
Function Get-ServerType {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ServerType 
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    #>
    Write-VerboseWriter("Calling: Get-ServerType")
    $returnServerType = [string]::Empty
    if($ServerType -like "VMware*") { $returnServerType = "VMware"}
    elseif($ServerType -like "*Microsoft Corporation*") { $returnServerType = "HyperV" }
    elseif($ServerType.Length -gt 0) {$returnServerType = "Physical"}
    else { $returnServerType = "Unknown" }
    
    Write-VerboseWriter("Returning: {0}" -f $returnServerType)
    return $returnServerType 
}