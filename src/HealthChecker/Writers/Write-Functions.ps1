
function Write-Red($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Red
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Yellow($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Yellow
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Green($message)
{
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Green
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Grey($message)
{
    Write-DebugLog $message
    Write-Host $message
    $message | Out-File ($OutputFullPath) -Append
}

function Write-VerboseOutput($message)
{
    Write-Verbose $message
    Write-DebugLog $message
    if($Script:VerboseEnabled)
    {
        $message | Out-File ($OutputFullPath) -Append
    }
}

function Write-DebugLog($message)
{
    if(![string]::IsNullOrEmpty($message))
    {
        $Script:Logger.WriteToFileOnly($message)
    }
}

Function Write-Break {
    Write-Host ""
}

#Function Version 1.1
Function Write-HostWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString 
)
    if($Script:Logger -ne $null)
    {
        $Script:Logger.WriteHost($WriteString)
    }
    elseif($HostFunctionCaller -eq $null)
    {
        Write-Host $WriteString
    }
    else
    {
        &$HostFunctionCaller $WriteString    
    }
}
    
Function Write-VerboseWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString 
)
    if($VerboseFunctionCaller -eq $null)
    {
            Write-Verbose $WriteString
    }
    else 
    {
        &$VerboseFunctionCaller $WriteString
    }
}

$Script:VerboseFunctionCaller = ${Function:Write-VerboseOutput}

#Function Version 1.0
Function Write-ScriptMethodHostWriter{
param(
[Parameter(Mandatory=$true)][string]$WriteString
)
    if($this.LoggerObject -ne $null)
    {
        $this.LoggerObject.WriteHost($WriteString) 
    }
    elseif($this.HostFunctionCaller -eq $null)
    {
        Write-Host $WriteString
    }
    else 
    {
        $this.HostFunctionCaller($WriteString)
    }
}

#Function Version 1.0
Function Write-ScriptMethodVerboseWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString
)
    if($this.LoggerObject -ne $null)
    {
        $this.LoggerObject.WriteVerbose($WriteString)
    }
    elseif($this.VerboseFunctionCaller -eq $null -and 
        $this.WriteVerboseData)
    {
        Write-Host $WriteString -ForegroundColor Cyan 
    }
    elseif($this.WriteVerboseData)
    {
        $this.VerboseFunctionCaller($WriteString)
    }
}