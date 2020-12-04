#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-Smb1ServerSettings/Get-Smb1ServerSettings.ps1
Function Get-Smb1ServerSettings {
[CmdletBinding()]
param(
[string]$ServerName = $env:COMPUTERNAME,
[scriptblock]$CatchActionFunction
)
#Function Version 1.2
<# 
Required Functions: 
    https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
    https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
#>

Write-VerboseWriter("Calling: Get-Smb1ServerSettings")
Write-VerboseWriter("Passed ServerName: {0}" -f $ServerName)
$smbServerConfiguration = Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock {Get-SmbServerConfiguration} -CatchActionFunction $CatchActionFunction -ScriptBlockDescription "Get-SmbServerConfiguration"

<#
Unknown 0
Failed to get Install Setting 1
Install is set to true 2
Install is set to false 4
Failed to get Block Setting 8
SMB1 is not being blocked 16
SMB1 is being blocked 32
#>

$smb1Status = 0

try
{
    $windowsFeature = Get-WindowsFeature "FS-SMB1" -ComputerName $ServerName -ErrorAction Stop
}
catch 
{
    Write-VerboseWriter("Failed to Get-WindowsFeature for FS-SMB1")
    if ($CatchActionFunction -ne $null)
    {
        & $CatchActionFunction
    }
}

if ($windowsFeature -eq $null)
{
    $smb1Status += 1
}
elseif ($windowsFeature.Installed)
{
    $smb1Status += 2
}
else
{
    $smb1Status += 4
}

if ($smbServerConfiguration -eq $null)
{
    $smb1Status += 8
}
elseif ($smbServerConfiguration.EnableSMB1Protocol)
{
    $smb1Status += 16
}
else
{
    $smb1Status += 32
}

$smb1ServerSettings = New-Object PSCustomObject
$smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "SmbServerConfiguration" -Value $smbServerConfiguration
$smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "WindowsFeature" -Value $windowsFeature
$smb1ServerSettings | Add-Member -MemberType NoteProperty -Name "Smb1Status" -Value $smb1Status

return $smb1ServerSettings

}