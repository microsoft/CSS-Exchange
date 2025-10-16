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

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 5002)
$listener.Start()

Start-Process "explorer.exe" $uri

try {
    while ($listener.Server.IsBound) {

        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 100
            continue
        }

        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = New-Object IO.StreamReader($stream)
        $writer = New-Object IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Read request line
        $requestLine = $reader.ReadLine()

        if (-not $requestLine) {
            # No valid request, close client and continue listening
            $client.Close()
            continue
        }

        $headers = @{}
        while (($line = $reader.ReadLine()) -and $line -ne "") {
            $parts = $line.Split(":", 2)
            if ($parts.Length -eq 2) { $headers[$parts[0].Trim()] = $parts[1].Trim() }
        }

        if ($requestLine -match "^PUT") {
            Write-Host "Browser tab was closed without saving changes."
            $writer.WriteLine("HTTP/1.1 200 OK")
            $writer.WriteLine("Content-Length: 0")
            $writer.WriteLine("Connection: close")
            $writer.WriteLine()
            $client.Close()
            break
        }

        elseif ($requestLine -match "^GET") {
            $pageContent = $htmlFileContent.Replace("var selectionTable = [];", "var selectionTable = $selectionTableJson;")
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($pageContent)
            $writer.WriteLine("HTTP/1.1 200 OK")
            $writer.WriteLine("Content-Type: text/html; charset=UTF-8")
            $writer.WriteLine("Content-Length: $($bytes.Length)")
            $writer.WriteLine("Connection: close")
            $writer.WriteLine()
            $stream.Write($bytes, 0, $bytes.Length)
        } elseif ($requestLine -match "^POST") {
            $contentLength = [int]$headers["Content-Length"]
            $buffer = New-Object byte[] $contentLength
            $stream.Read($buffer, 0, $contentLength) | Out-Null
            $body = [System.Text.Encoding]::UTF8.GetString($buffer)
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

            $writer.WriteLine("HTTP/1.1 200 OK")
            $writer.WriteLine("Content-Length: 0")
            $writer.WriteLine("Connection: close")
            $writer.WriteLine()

            $client.Close()
            break
        }
        $client.Close()
    }
} finally {
    $listener.Stop()
}

if (Test-Path $outputPath) {
    ShowCommandToHost
}
