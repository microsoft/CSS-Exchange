#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-ServerRebootPending/Get-ServerRebootPending.ps1
Function Get-ServerRebootPending {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$ServerName,
    [Parameter(Mandatory=$false)][scriptblock]$CatchActionFunction
    )
    #Function Version 1.0
    <# 
    Required Functions: 
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-VerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
    #>
    Function Get-PendingFileReboot {
        try 
        {
            if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name PendingFileRenameOperations -ErrorAction Stop))
            {
                return $true 
            }
            else 
            {
                return $false 
            }
        }
        catch 
        {
            throw 
        }
    }
    Function Get-PendingSCCMReboot {
        try 
        {
            $sccmReboot = Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction Stop 
            if($sccmReboot -and ($sccmReboot.RebootPending -or $sccmReboot.IsHardRebootPending))
            {
                return $true 
            }
        }
        catch 
        {
            throw 
        }
    }
    Function Get-PathTestingReboot {
    param(
    [string]$TestingPath 
    )
        if(Test-Path $TestingPath)
        {
            return $true 
        }
        else 
        {
            return $false 
        }
    }
    
    Write-VerboseWriter("Calling: Get-ServerRebootPending")
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingFileReboot} -ScriptBlockDescription "Get-PendingFileReboot" -CatchActionFunction $CatchActionFunction)
    {
        Write-VerboseWriter("Get-PendingFileReboot Determined Reboot is pending. Registry HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\ item properties of PendingFileRenameOperations.")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PendingSCCMReboot} -ScriptBlockDescription "Get-PendingSCCMReboot" -CatchActionFunction $CatchActionFunction)
    {
        Write-VerboseWriter("Get-PendingSCCMReboot determined reboot is pending.")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} -ScriptBlockDescription "Get-PendingAutoUpdateReboot" -CatchActionFunction $CatchActionFunction -ArgumentList "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
    {
        Write-VerboseWriter("Get-PathTestingReboot for HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending determined reboot is pending")
        return $true 
    }
    if(Invoke-ScriptBlockHandler -ComputerName $ServerName -ScriptBlock ${Function:Get-PathTestingReboot} -ScriptBlockDescription "Get-PendingAutoUpdateReboot" -CatchActionFunction $CatchActionFunction -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    {
        Write-VerboseWriter("Get-PathTestingReboot for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired determined reboot is pending")
        return $true 
    }
    Write-VerboseWriter("Passed all reboot checks.")
    return $false 
}