
function Write-Red($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Red
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Yellow($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Yellow
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Green($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Green
    $message | Out-File ($OutputFullPath) -Append
}

function Write-Grey($message) {
    Write-DebugLog $message
    Write-Host $message
    $message | Out-File ($OutputFullPath) -Append
}

function Write-VerboseOutput($message) {
    Write-Verbose $message
    Write-DebugLog $message
    if ($Script:VerboseEnabled) {
        $message | Out-File ($OutputFullPath) -Append
    }
}

function Write-DebugLog($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:Logger.WriteToFileOnly($message)
    }
}

Function Write-Break {
    Write-Host ""
}

#Function Version 1.1
Function Write-HostWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $Script:Logger) {
        $Script:Logger.WriteHost($WriteString)
    } elseif ($null -eq $HostFunctionCaller) {
        Write-Host $WriteString
    } else {
        &$HostFunctionCaller $WriteString
    }
}

Function Write-VerboseWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -eq $VerboseFunctionCaller) {
        Write-Verbose $WriteString
    } else {
        &$VerboseFunctionCaller $WriteString
    }
}

$Script:VerboseFunctionCaller = ${Function:Write-VerboseOutput}