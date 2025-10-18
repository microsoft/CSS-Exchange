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

$tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 5002)
$tcpListener.Start()

& explorer.exe $uri

function ReadRequest($stream) {
    Write-Debug "Reading request from stream"
    $reader = New-Object System.IO.StreamReader($stream, [Text.Encoding]::UTF8, $false, 1024, $true)
    $line = $reader.ReadLine()
    if (-not $line) {
        return $null
    }

    $req = [PSCustomObject]@{
        RequestLine = $line
        Method      = $null
        Path        = $null
        Version     = "HTTP/1.1"
        Headers     = @{}
        Body        = [byte[]]::new(0)
    }

    $parts = $line -split ' '
    if ($parts.Length -ge 2) { $req.Method = $parts[0]; $req.Path = $parts[1] }
    if ($parts.Length -ge 3) { $req.Version = $parts[2] }

    # headers
    while ($true) {
        $h = $reader.ReadLine()
        if ($null -eq $h -or $h -eq '') { break }
        $kv = $h -split ":\s*", 2
        if ($kv.Length -eq 2) { $req.Headers[$kv[0]] = $kv[1] }
    }

    # body (simple Content-Length handling)
    if ($req.Headers.ContainsKey("Content-Length")) {
        $len = [int]$req.Headers["Content-Length"]
        if ($len -gt 0) {
            $buf = New-Object char[] $len
            $total = 0
            while ($total -lt $len) {
                $read = $reader.Read($buf, $total, $len - $total)
                if ($read -le 0) { break }
                $total += $read
            }
            $bodyText = [Text.Encoding]::UTF8.GetString($buf, 0, $total)
            $req.Body = $bodyText
        }
    }

    $reader.Close()

    Write-Debug "Request read: $($req.Method) $($req.Path), $($req.Headers.Count) headers, $($req.Body.Length) body bytes"

    return $req
}

function WriteResponse {
    param(
        [System.IO.Stream]$Stream,
        [int]$Status = 200,
        [string]$ContentType = "text/plain; charset=utf-8",
        [byte[]]$BodyBytes
    )

    Write-Debug "Writing response to stream: $Status, $($BodyBytes.Length) body bytes"

    $statusText = @{
        200 = "OK"; 400 = "Bad Request"; 404 = "Not Found"; 500 = "Internal Server Error"
    }[$Status]

    if (-not $BodyBytes) { $BodyBytes = [byte[]]::new(0) }

    $header =
    "HTTP/1.1 $Status $statusText`r`n" +
    "Date: $([DateTime]::UtcNow.ToString('r'))`r`n" +
    "Server: ExTRA-TcpListener`r`n" +
    "Content-Type: $ContentType`r`n" +
    "Content-Length: $($BodyBytes.Length)`r`n" +
    "Connection: close`r`n`r`n"

    $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    if ($BodyBytes.Length -gt 0) { $stream.Write($BodyBytes, 0, $BodyBytes.Length) }
    $stream.Flush()

    Write-Debug "Response written: $Status $statusText, $($BodyBytes.Length) body bytes"
}

$putTimer = [Diagnostics.Stopwatch]::new()

try {
    while ($true) {
        if ($putTimer.Elapsed.TotalSeconds -gt 1) {
            Write-Host "Browser tab was closed without saving changes."
            break
        }

        if (-not $tcpListener.Pending()) {
            Start-Sleep -Milliseconds 100
            continue
        }

        if ($putTimer.IsRunning) {
            $putTimer.Stop()
            $putTimer.Reset()
        }

        $client = $tcpListener.AcceptTcpClient()
        $stream = $client.GetStream()
        $request = ReadRequest $stream

        if ($request.Method -eq "PUT") {
            WriteResponse -Stream $stream -Status 200
            $client.Close()

            # The user might have closed the tab, or might have clicked Refresh.
            # They both fire the same event. So, wait a moment and see if we get
            # another request. If we don't, tab was closed.
            $putTimer.Start()
        } elseif ($request.Method -eq "GET") {
            Write-Host "Showing tag selector UI in the default browser."
            $pageContent = $htmlFileContent.Replace("var selectionTable = [];", "var selectionTable = $selectionTableJson;")
            $pageContentUTF8 = [System.Text.Encoding]::UTF8.GetBytes($pageContent)
            WriteResponse -Stream $stream -Status 200 -ContentType "text/html; charset=utf-8" -BodyBytes $pageContentUTF8
            $client.Close()
        } elseif ($request.Method -eq "POST") {
            WriteResponse -Stream $stream -Status 200
            $client.Close()

            $tagInfo = ConvertFrom-Json $request.Body
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
        } else {
            WriteResponse -Stream $stream -Status 400
            $client.Close()
        }
    }
} finally {
    $tcpListener.Stop()
}

if (Test-Path $outputPath) {
    ShowCommandToHost
}
