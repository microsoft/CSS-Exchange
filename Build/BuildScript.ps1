param(
[object]$ScriptVersion
)

if ($null -eq $ScriptVersion)
{
    $ScriptVersion = .\GetScriptVersion.ps1
}

$loadJson = Get-Content .\BuildScript.config.json
$config = $loadJson | ConvertFrom-Json | Sort-Object LoadOrder

[System.Collections.Generic.List[System.Object]]$healthChecker = New-Object -TypeName System.Collections.Generic.List[System.Object]
[System.Collections.Generic.List[System.Object]]$loadedFiles = New-Object -TypeName System.Collections.Generic.List[System.Object]

$scriptVersionAdded = $false

foreach ($configItem in $config)
{
    [string]$filePath = $configItem.Path
    $loadFiles = @()
    if ($filePath.EndsWith("\"))
    {
        $allFiles = Get-ChildItem $filePath | Where-Object {$_.name.EndsWith(".ps1")}
        if ($null -ne $configItem.ExcludeFiles.FileName)
        {
            $allFiles = $allFiles | Where-Object {!$configItem.ExcludeFiles.FileName.Contains($_.Name)}
        }
        foreach ($file in $allFiles)
        {
            $loadFiles += $file.VersionInfo.FileName
        }
    }
    else 
    {
        $loadFiles = (Get-ChildItem $filePath).VersionInfo.FileName
    }

    foreach ($file in $loadFiles)
    {
        if ($loadedFiles.Contains($file))
        {
            continue
        }

        $getContent = Get-Content $file
        
        foreach($line in $getContent)
        {
            $healthChecker.Add($line)
        }

        if (!$scriptVersionAdded)
        {
            $healthChecker.Add(("`$healthCheckerVersion = `"{0}.{1}.{2}`"" -f $ScriptVersion.Major, $ScriptVersion.Minor, $ScriptVersion.BuildRevision))
            $scriptVersionAdded = $true
        }

        $healthChecker.Add([string]::Empty)

        $loadedFiles.Add($file)
    }
}

$healthChecker | Out-File .\HealthChecker.ps1 -Encoding utf8
$healthChecker | Out-File .\HealthChecker.txt -Encoding utf8