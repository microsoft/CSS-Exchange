# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [switch]$ShowCommandOnly
)

. $PSScriptRoot\GetTagsFromFileContent.ps1

function ShowCommandToHost {
    Write-Host "The trace can be created, deleted, started, and stopped from the command line or PowerShell"
    Write-Host
    Write-Host "To delete a previously created data collector set:"
    Write-Host
    Write-Host "logman delete ExchangeDebugTraces" -ForegroundColor Green
    Write-Host
    Write-Host "To create a data collector which is non-circular and stops at 1 GB:"
    Write-Host
    Write-Host "logman create trace ExchangeDebugTraces -p `"{79bb49e6-2a2c-46e4-9167-fa122525d540}`" -o c:\tracing\trace.etl -ow -f bin -max 1024 -mode globalsequence" -ForegroundColor Green
    Write-Host
    Write-Host "To create a data collector which is circular and stops at 2 GB:"
    Write-Host
    Write-Host "logman create trace ExchangeDebugTraces -p `"{79bb49e6-2a2c-46e4-9167-fa122525d540}`" -o c:\tracing\trace.etl -ow -f bincirc -max 2048 -mode globalsequence" -ForegroundColor Green
    Write-Host
    Write-Host "To create a data collector which is non-circular and creates a new file every 512 MB until you stop it manually:"
    Write-Host
    Write-Host "logman create trace ExchangeDebugTraces -p `"{79bb49e6-2a2c-46e4-9167-fa122525d540}`" -o c:\tracing\trace.etl -ow -f bin -max 512 -cnf 0 -mode globalsequence" -ForegroundColor Green
    Write-Host
    Write-Host "To start the trace:"
    Write-Host
    Write-Host "logman start ExchangeDebugTraces" -ForegroundColor Green
    Write-Host
    Write-Host "To stop the trace:"
    Write-Host
    Write-Host "logman stop ExchangeDebugTraces" -ForegroundColor Green
    Write-Host
    Write-Host "The collector can also be started and stopped from Perfmon."
}

if ($ShowCommandOnly) {
    ShowCommandToHost
    return
}

$selectionTableJsonBytes = Get-Content "$PSScriptRoot\SelectionTable.json" -AsByteStream -Raw

$selectionTableJson = [System.Text.Encoding]::UTF8.GetString($selectionTableJsonBytes)

$selectionTable = ConvertFrom-Json $selectionTableJson

$htmlFileBytes = Get-Content "$PSScriptRoot\ui.html" -AsByteStream -Raw

$htmlFileContent = [System.Text.Encoding]::UTF8.GetString($htmlFileBytes)

$uri = "http://localhost:5002/"

$outputPath = Join-Path $PSScriptRoot "EnabledTraces.config"

$alreadySelectedTags = $null

if (Test-Path $outputPath) {
    $alreadySelectedTags = GetTagsFromFileContent (Get-Content $outputPath)
}

if ($null -ne $alreadySelectedTags) {
    foreach ($category in $alreadySelectedTags) {
        $selectedTags = $category.tags | ForEach-Object { $_.name }
        $categoryToUpdate = $selectionTable | Where-Object { $_.name -eq $category.name }
        $categoryToUpdate.tags | ForEach-Object {
            if ($selectedTags.Contains($_.name)) {
                $_.isSelected = $true
            }
        }
    }
}

$selectionTableJson = $selectionTable | ConvertTo-Json -Depth 4

$httpListener = New-Object System.Net.HttpListener
$httpListener.Prefixes.Add($uri)
$httpListener.Start()

& explorer.exe $uri

try {
    while ($httpListener.IsListening) {
        $task = $httpListener.GetContextAsync()
        while (-not $task.AsyncWaitHandle.WaitOne(100)) {
            Start-Sleep -Milliseconds 100
        }

        $context = $task.GetAwaiter().GetResult()

        if ($context.Request.HttpMethod -eq "PUT") {
            $context.Response.StatusCode = 200
            $context.Response.Close()

            # The user might have closed the tab, or might have clicked Refresh.
            # They both fire the same event. So, wait a moment and see if we get
            # another request. If we don't, tab was closed.
            $task = $httpListener.GetContextAsync()
            if (-not $task.AsyncWaitHandle.WaitOne(1000)) {
                Write-Host "Browser tab was closed without saving changes."
                break
            } else {
                $context = $task.GetAwaiter().GetResult()
            }
        }

        if ($context.Request.HttpMethod -eq "GET") {
            Write-Host "Showing tag selector UI in the default browser."
            $pageContent = $htmlFileContent.Replace("var selectionTable = [];", "var selectionTable = $selectionTableJson;")
            $pageContentUTF8 = [System.Text.Encoding]::UTF8.GetBytes($pageContent)
            $context.Response.StatusCode = 200
            $context.Response.OutputStream.Write($pageContentUTF8, 0, $pageContentUTF8.Length)
            $context.Response.Close()
        } elseif ($context.Request.HttpMethod -eq "POST") {
            $reader = New-Object System.IO.StreamReader($context.Request.InputStream, "UTF8")
            $body = $reader.ReadToEnd()
            $context.Response.StatusCode = 200
            $context.Response.Close()
            $tagInfo = ConvertFrom-Json $body
            $selectedTags = @()
            foreach ($category in $tagInfo) {
                $selectedTagsForThisCategory = $category.tags | Where-Object { $_.isSelected }
                if ($null -ne $selectedTagsForThisCategory) {
                    $tagString = [string]::Join(',', ($selectedTagsForThisCategory | ForEach-Object { $_.name }))
                    $selectedTags += $category.name + ":" + $tagString
                }
            }

            $linesToSave = @()
            $linesToSave += "TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd"

            Write-Host
            Write-Host "Selected tags:"
            foreach ($line in $selectedTags) {
                Write-Host $line
                $linesToSave += $line
            }

            $linesToSave += "FilteredTracing:No"
            $linesToSave += "InMemoryTracing:No"

            Write-Host

            $outputPath = Join-Path $PSScriptRoot "EnabledTraces.config"

            Write-Host "Saving" $outputPath

            [IO.File]::WriteAllLines($outputPath, $linesToSave)

            break
        }
    }
} finally {
    $httpListener.Close()
}

if (Test-Path $outputPath) {
    ShowCommandToHost
}
