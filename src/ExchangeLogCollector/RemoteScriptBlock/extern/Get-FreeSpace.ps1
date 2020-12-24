#Template master: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Get-FreeSpace/Get-FreeSpace.ps1
Function Get-FreeSpace {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][ValidateScript({$_.ToString().EndsWith("\")})][string]$FilePath,
    [Parameter(Mandatory=$false,Position=1)][object]$PassedObjectParameter
    )
    
    #Function Version 1.3
    <#
    Required Functions:
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-InvokeCommandReturnVerboseWriter.ps1
        https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
    #>
    if($PassedObjectParameter -ne $null)
    {
        if($PassedObjectParameter.FilePath -ne $null)
        {
            $FilePath = $PassedObjectParameter.FilePath
        }
        else 
        {
            $FilePath = $PassedObjectParameter
        }
        $InvokeCommandReturnWriteArray = $true 
    }
    $stringArray = @()
    Write-InvokeCommandReturnVerboseWriter("Calling: Get-FreeSpace")
    Write-InvokeCommandReturnVerboseWriter("Passed: [string]FilePath: {0}" -f $FilePath)
    
    Function Update-TestPath {
    param(
    [Parameter(Mandatory=$true)][string]$FilePath 
    )
        $updateFilePath = $FilePath.Substring(0,$FilePath.LastIndexOf("\", $FilePath.Length - 2)+1)
        return $updateFilePath
    }
    
    Function Get-MountPointItemTarget{
    param(
    [Parameter(Mandatory=$true)][string]$FilePath 
    )
        $itemTarget = [string]::Empty
        if(Test-Path $testPath)
        {
            $item = Get-Item $FilePath
            if($item.Target -like "Volume{*}\")
            {
                Write-InvokeCommandReturnVerboseWriter("File Path appears to be a mount point target: {0}" -f $item.Target)
                $itemTarget = $item.Target
            }
            else {
                Write-InvokeCommandReturnVerboseWriter("Path didn't appear to be a mount point target")    
            }
        }
        else {
            Write-InvokeCommandReturnVerboseWriter("Path isn't a true path yet.")
        }
        return $itemTarget    
    }
    
    Function Invoke-ReturnValue {
    param(
    [Parameter(Mandatory=$true)][int]$FreeSpaceSize
    )
        if($InvokeCommandReturnWriteArray)
        {
            $hashTable = @{"ReturnObject"=$freeSpaceSize}
            Set-Variable stringArray -Value ($stringArray += $hashTable) -Scope 1 
            return $stringArray
        }
        return $FreeSpaceSize
    }
    
    $drivesList = Get-WmiObject Win32_Volume -Filter "drivetype = 3"
    $testPath = $FilePath
    $freeSpaceSize = -1 
    while($true)
    {
        if($testPath -eq [string]::Empty)
        {
            Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
            return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
        }
        Write-InvokeCommandReturnVerboseWriter("Trying to find path that matches path: {0}" -f $testPath)
        foreach($drive in $drivesList)
        {
            if($drive.Name -eq $testPath)
            {
                Write-InvokeCommandReturnVerboseWriter("Found a match")
                $freeSpaceSize = $drive.FreeSpace / 1GB 
                Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
            }
            Write-InvokeCommandReturnVerboseWriter("Drive name: '{0}' didn't match" -f $drive.Name)
        }
    
        $itemTarget = Get-MountPointItemTarget -FilePath $testPath
        if($itemTarget -ne [string]::Empty)
        {
            foreach($drive in $drivesList)
            {
                if($drive.DeviceID.Contains($itemTarget))
                {
                    $freeSpaceSize = $drive.FreeSpace / 1GB 
                    Write-InvokeCommandReturnVerboseWriter("Have {0}GB of Free Space" -f $freeSpaceSize)
                    return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
                }
                Write-InvokeCommandReturnVerboseWriter("DeviceID didn't appear to match: {0}" -f $drive.DeviceID)
            }
            if($freeSpaceSize -eq -1)
            {
                Write-InvokeCommandReturnHostWriter("Unable to fine a drive that matches the file path: {0}" -f $FilePath)
                Write-InvokeCommandReturnHostWriter("This shouldn't have happened.")
                return (Invoke-ReturnValue -FreeSpaceSize $freeSpaceSize)
            }
        }
        $testPath = Update-TestPath -FilePath $testPath
    }
}