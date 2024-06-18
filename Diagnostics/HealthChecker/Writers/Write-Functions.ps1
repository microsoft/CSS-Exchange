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
        try {
            $stringOutput = $null
            $params = @{
                Properties         = $OutColumns.SelectProperties
                ColorizerFunctions = $OutColumns.ColorizerFunctions
                IndentSpaces       = $OutColumns.IndentSpaces
                StringOutput       = ([ref]$stringOutput)
            }
            $OutColumns.DisplayObject | Out-Columns @params
            $stringOutput | Out-File ($Script:OutputFullPath) -Append
            Write-DebugLog $stringOutput
        } catch {
            # We do not want to call Invoke-CatchActions here because we want the issues reported.
            Write-Verbose "Failed to export Out-Columns. Inner Exception: $_"
            $s = $OutColumns.DisplayObject | Out-String
            Write-DebugLog $s
        }
    }
}

function Write-Break {
    Write-Host ""
}
