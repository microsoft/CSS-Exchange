$uri = "http://localhost:5002/"

$outputPath = Join-Path $PSScriptRoot "EnabledTraces.config"

function GetTagsFromFile($file) {
    $tags = Get-Content $file | ForEach-Object {
        if ($_ -match "(^TraceLevels|^InMemoryTracing|^FilteredTracing)") {
            # Skip these lines
        }
        else {

            [PSCustomObject]@{
                name       = $_.Substring(0, $_.IndexOf(':'))
                isSelected = $false
                tags       = @($_.Substring($_.IndexOf(':') + 1).Split(',') | Sort-Object | ForEach-Object {
                        [PSCustomObject]@{
                            name       = $_
                            isSelected = $false
                        }
                    })
            }
        }
    }

    return $tags
}

$ex2016Tags = GetTagsFromFile "$PSScriptRoot\tags2016.txt"

$alreadySelectedTags = $null

if (Test-Path $outputPath) {
    $alreadySelectedTags = GetTagsFromFile $outputPath
}

if ($null -ne $alreadySelectedTags) {
    foreach ($category in $alreadySelectedTags) {
        $selectedTags = $category.tags | ForEach-Object { $_.name }
        $categoryToUpdate = $ex2016Tags | Where-Object { $_.name -eq $category.name }
        $categoryToUpdate.tags | ForEach-Object {
            if ($selectedTags.Contains($_.name)) {
                $_.isSelected = $true
            }
        }
    }
}

$ex2016Tags = ConvertTo-Json $ex2016Tags -Depth 3

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
            }
            else {
                $context = $task.GetAwaiter().GetResult()
            }          
        }

        if ($context.Request.HttpMethod -eq "GET") {
            Write-Host "Showing tag selector UI in the default browser."
            $pageContent = [IO.File]::ReadAllText("$PSScriptRoot\ui.html")
            $pageContent = $pageContent.Replace("var exchange2016Tags = [];", "var exchange2016Tags = $ex2016Tags;")
            $pageContentUTF8 = [System.Text.Encoding]::UTF8.GetBytes($pageContent)
            $context.Response.StatusCode = 200
            $context.Response.OutputStream.Write($pageContentUTF8, 0, $pageContentUTF8.Length)
            $context.Response.Close()
        }
        elseif ($context.Request.HttpMethod -eq "POST") {
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
}
finally {
    $httpListener.Close()
}

if (Test-Path $outputPath) {
    $choice = Read-Host "Would you like to start an ExTRA with the current settings? (y/n) "

    if ($choice -eq "y") {
        Copy-Item $outputPath C:\EnabledTraces.config -Force

        $collectorExistsTest = & logman query ExchangeDebugTraces
        if ($collectorExistsTest -match "not found") {
            & cmd /c "logman create trace ExchangeDebugTraces -p {79bb49e6-2a2c-46e4-9167-fa122525d540} -o c:\tracing\trace.etl -ow -f bin -max 1024"
        }

        & logman start ExchangeDebugTraces

        Write-Host
        Write-Host "To stop the trace run the following command:"
        Write-Host "logman stop ExchangeDebugTraces"
    }
}