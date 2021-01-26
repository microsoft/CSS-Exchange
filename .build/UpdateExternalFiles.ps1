#Only run if you need to pull an update.
#TODO: Add ability to update single file vs all.
$repoRoot = Get-Item "$PSScriptRoot\.."
Write-Host $repoRoot
$externReproRoot = "$PSScriptRoot\.externRepo"
$reproPublicScripts = "$externReproRoot\PublicPowerShellFunctions"
$rootPath = "$repoRoot\src"
$gitCloneUrl = 'https://github.com/dpaulson45/PublicPowerShellFunctions.git'
$lineHeader = '#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/'

try {
    if (!(Test-Path $externReproRoot)) {
        New-Item -Path $externReproRoot -ItemType Directory | Out-Null
        Set-Location $externReproRoot
        git clone $gitCloneUrl
    } elseif (!(Test-Path $reproPublicScripts)) {
        Set-Location $externReproRoot
        git clone $gitCloneUrl
    } else {
        Set-Location $reproPublicScripts
        git pull
    }

    $files = Get-ChildItem $rootPath -Recurse | Where-Object { $_.VersionInfo.FileName -like "*\extern\*" -and $_.VersionInfo.FileName.EndsWith(".ps1")}

    Set-Location $reproPublicScripts

    foreach ($file in $files) {
        $filePath = $file.VersionInfo.FileName
        $backup = $filePath.Replace(".ps1", ".bak")

        $scriptContent = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent.AddRange([IO.File]::ReadAllLines($filePath))

        if (!$scriptContent[0].Contains($lineHeader)) {
            Write-Host "Failed to find correct header info for file: $filePath"
            exit
        }
        #0 Location on the net
        #1 Version Number
        $originalLine =$scriptContent[0]
        $scriptGeneralFileLocation = $originalLine.Replace($lineHeader, "").Replace("/", "\")
        $scriptVersionNumber = $scriptContent[1].Trim()

        $reproScriptVersion = "#v$([DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $scriptGeneralFileLocation)).ToString("yy.MM.dd.HHmm"))"

        if ($scriptVersionNumber -ne $reproScriptVersion) {
            $scriptContent = New-Object 'System.Collections.Generic.List[string]'
            $scriptContent.AddRange([IO.File]::ReadAllLines("$reproPublicScripts\$scriptGeneralFileLocation"))

            #Remove extra stuff.
            $i = 0
            $startRemoveIndex = 0
            $count = 0
            $foundExtra = $false
            foreach ($line in $scriptContent) {

                if ($line.Contains("Required Functions:")) {
                    $foundExtra = $true
                    $startRemoveIndex = $i - 1
                } elseif ($foundExtra -and
                    $line.Contains("#>")) {
                        $count = $i - $startRemoveIndex + 1
                        break
                }
                $i++ 
            }

            if ($foundExtra) {
                $scriptContent.RemoveRange($startRemoveIndex, $count)
                $scriptContent.Insert($startRemoveIndex, "    #Function Version $reproScriptVersion")
            }

            $scriptContent.Insert(0,$reproScriptVersion)
            $scriptContent.Insert(0,$originalLine)

            Write-Host "Updating Script: $filePath"

            Move-Item -Path $filePath -Destination $backup -Force
            Set-Content -Path $filePath -Value $scriptContent
        }
    }

} finally {
    Set-Location $PSScriptRoot
}
