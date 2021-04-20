
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

$Script:VerboseFunctionCaller = ${Function:Write-VerboseOutput}