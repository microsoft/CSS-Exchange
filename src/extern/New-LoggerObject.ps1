#Master Template: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/New-LoggerObject/New-LoggerObject.ps1
Function New-LoggerObject {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)][string]$LogDirectory = ".",
    [Parameter(Mandatory=$false)][string]$LogName = "Script_Logging",
    [Parameter(Mandatory=$false)][bool]$EnableDateTime = $true,
    [Parameter(Mandatory=$false)][bool]$IncludeDateTimeToFileName = $true,
    [Parameter(Mandatory=$false)][int]$MaxFileSizeInMB = 10,
    [Parameter(Mandatory=$false)][int]$CheckSizeIntervalMinutes = 10,
    [Parameter(Mandatory=$false)][int]$NumberOfLogsToKeep = 10,
    [Parameter(Mandatory=$false)][bool]$VerboseEnabled,
    [Parameter(Mandatory=$false)][scriptblock]$HostFunctionCaller,
    [Parameter(Mandatory=$false)][scriptblock]$VerboseFunctionCaller
    )
    
        #Function Version 1.2
        <# 
        Required Functions: 
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-ScriptMethodHostWriter.ps1
            https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-VerboseWriters/Write-ScriptMethodVerboseWriter.ps1
        #>
    
        ########################
        #
        # Template Functions
        #
        ########################
    
        Function Write-ToLog {
        param(
        [object]$WriteString,
        [string]$LogLocation
        )
            $WriteString | Out-File ($LogLocation) -Append
        }
    
        ########################
        #
        # End Template Functions
        #
        ########################
    
    
        ########## Parameter Binding Exceptions ##############
        # throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ParameterName" 
        if($LogDirectory -eq ".")
        {
            $LogDirectory = (Get-Location).Path
        }
        if([string]::IsNullOrEmpty($LogName))
        {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogName" 
        }
        if(!(Test-Path $LogDirectory))
        {
            throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LogDirectory" 
        }
    
        $loggerObject = New-Object pscustomobject 
        $loggerObject | Add-Member -MemberType NoteProperty -Name "FileDirectory" -Value $LogDirectory
        $loggerObject | Add-Member -MemberType NoteProperty -Name "FileName" -Value $LogName
        $loggerObject | Add-Member -MemberType NoteProperty -Name "FullPath" -Value $fullLogPath
        $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceBaseName" -Value ([string]::Empty)
        $loggerObject | Add-Member -MemberType NoteProperty -Name "EnableDateTime" -Value $EnableDateTime
        $loggerObject | Add-Member -MemberType NoteProperty -Name "IncludeDateTimeToFileName" -Value $IncludeDateTimeToFileName
        $loggerObject | Add-Member -MemberType NoteProperty -Name "MaxFileSizeInMB" -Value $MaxFileSizeInMB
        $loggerObject | Add-Member -MemberType NoteProperty -Name "CheckSizeIntervalMinutes" -Value $CheckSizeIntervalMinutes
        $loggerObject | Add-Member -MemberType NoteProperty -Name "NextFileCheckTime" -Value ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        $loggerObject | Add-Member -MemberType NoteProperty -Name "InstanceNumber" -Value 1
        $loggerObject | Add-Member -MemberType NoteProperty -Name "NumberOfLogsToKeep" -Value $NumberOfLogsToKeep
        $loggerObject | Add-Member -MemberType NoteProperty -Name "WriteVerboseData" -Value $VerboseEnabled
        $loggerObject | Add-Member -MemberType NoteProperty -Name "PreventLogCleanup" -Value $false
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "ToLog" -Value ${Function:Write-ToLog}
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHostWriter" -Value ${Function:Write-ScriptMethodHostWriter}
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerboseWriter" -Value ${Function:Write-ScriptMethodVerboseWriter}
    
        if($HostFunctionCaller -ne $null)
        {
            $loggerObject | Add-Member -MemberType ScriptMethod -Name "HostFunctionCaller" -Value $HostFunctionCaller
        }
        if($VerboseFunctionCaller -ne $null)
        {
            $loggerObject | Add-Member -MemberType ScriptMethod -Name "VerboseFunctionCaller" -Value $VerboseFunctionCaller
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteHost" -Value {
            param(
            [object]$LoggingString
            )
            if($LoggingString -eq $null)
            {
                throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
            }
    
            if($this.EnableDateTime)
            {
                $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
            }
    
            $this.WriteHostWriter($LoggingString)
            $this.ToLog($LoggingString, $this.FullPath)
            $this.LogUpKeep()
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteVerbose" -Value {
            param(
            [object]$LoggingString
            )
            if($LoggingString -eq $null)
            {
                throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
            }
    
            if($this.EnableDateTime)
            {
                $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
            }
            $this.WriteVerboseWriter($LoggingString)
            $this.ToLog($LoggingString, $this.FullPath)
            $this.LogUpKeep() 
    
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "WriteToFileOnly" -Value {
            param(
            [object]$LoggingString
            )
            if($LoggingString -eq $null)
            {
                throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid LoggingString"
            }
    
            if($this.EnableDateTime)
            {
                $LoggingString = "[{0}] : {1}" -f [System.DateTime]::Now, $LoggingString
            }
            $this.ToLog($LoggingString, $this.FullPath)
            $this.LogUpKeep()
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "UpdateFileLocation" -Value{
    
            if($this.FullPath -eq $null)
            {
                if($this.IncludeDateTimeToFileName)
                {
                    $this.InstanceBaseName = "{0}_{1}" -f $this.FileName, ((Get-Date).ToString('yyyyMMddHHmmss'))
                    $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
                }
                else 
                {
                    $this.InstanceBaseName = "{0}" -f $this.FileName
                    $this.FullPath = "{0}\{1}.txt" -f $this.FileDirectory, $this.InstanceBaseName
                }
            }
            else 
            {
    
                do{
                    $this.FullPath = "{0}\{1}_{2}.txt" -f $this.FileDirectory, $this.InstanceBaseName, $this.InstanceNumber
                    $this.InstanceNumber++
                }while(Test-Path $this.FullPath)
                $this.WriteVerbose("Updated to New Log")
            }
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "LogUpKeep" -Value {
    
            if($this.NextFileCheckTime -gt [System.DateTime]::Now)
            {
                return 
            }
            $this.NextFileCheckTime = (Get-Date).AddMinutes($this.CheckSizeIntervalMinutes)
            $this.CheckFileSize()
            $this.CheckNumberOfFiles()
            $this.WriteVerbose("Did Log Object Up Keep")
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckFileSize" -Value {
    
            $item = Get-ChildItem $this.FullPath
            if(($item.Length / 1MB) -gt $this.MaxFileSizeInMB)
            {
                $this.UpdateFileLocation()
            }
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "CheckNumberOfFiles" -Value {
    
            $filter = "{0}*" -f $this.InstanceBaseName
            $items = Get-ChildItem -Path $this.FileDirectory | ?{$_.Name -like $filter}
            if($items.Count -gt $this.NumberOfLogsToKeep)
            {
                do{
                    $items | Sort-Object LastWriteTime | Select -First 1 | Remove-Item -Force 
                    $items = Get-ChildItem -Path $this.FileDirectory | ?{$_.Name -like $filter}
                }while($items.Count -gt $this.NumberOfLogsToKeep)
            }
        }
    
        $loggerObject | Add-Member -MemberType ScriptMethod -Name "RemoveLatestLogFile" -Value {
    
            if(!$this.PreventLogCleanup)
            {
                $item = Get-ChildItem $this.FullPath
                Remove-Item $item -Force
            }
        }
    
        $loggerObject.UpdateFileLocation()
        try 
        {
            "[{0}] : Creating a new logger instance" -f [System.DateTime]::Now | Out-File ($loggerObject.FullPath) -Append
        }
        catch 
        {
            throw 
        }
    
        return $loggerObject
    }