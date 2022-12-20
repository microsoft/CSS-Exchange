# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Out-Columns.ps1
function Write-Red($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Red
    Write-HostLog $message
}

function Write-Yellow($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Yellow
    Write-HostLog $message
}

function Write-Green($message) {
    Write-DebugLog $message
    Write-Host $message -ForegroundColor Green
    Write-HostLog $message
}

function Write-Grey($message) {
    Write-DebugLog $message
    Write-Host $message
    Write-HostLog $message
}

function Write-DebugLog($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:Logger = $Script:Logger | Write-LoggerInstance $message
    }
}

function Write-HostLog ($message) {
    if ($Script:OutputFullPath) {
        $message | Out-File ($Script:OutputFullPath) -Append
    }
}

function Write-OutColumns($OutColumns) {
    if ($null -ne $OutColumns) {
        $stringOutput = $null
        $OutColumns.DisplayObject |
            Out-Columns -Properties $OutColumns.SelectProperties `
                -ColorizerFunctions $OutColumns.ColorizerFunctions `
                -IndentSpaces $OutColumns.IndentSpaces `
                -StringOutput ([ref]$stringOutput)
        $stringOutput | Out-File ($Script:OutputFullPath) -Append
        Write-DebugLog $stringOutput
    }
}

function Write-Break {
    Write-Host ""
}
