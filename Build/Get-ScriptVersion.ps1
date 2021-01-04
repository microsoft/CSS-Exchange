# Get-ScriptVersion.ps1 - used to get and set the script version
param(
    [string]$GitHubWebRequestUri,
    [string]$ScriptVersion
)

try {
    $webRequest = Invoke-WebRequest $GitHubWebRequestUri -UseBasicParsing
    $json = ConvertFrom-Json -InputObject $webRequest.Content
    $tagString = $json[0].tag_name
    $split = $tagString.Split(".")
    $currentMajor = [double]$split[0].Replace("v", "")
    $currentMinor = [double]$split[1]
    $buildRevision = [double]$split[2]

    $split = $ScriptVersion.Split(".")
    $major = [double]$split[0]
    $minor = [double]$split[1]

    if ($currentMajor -ne $major -or
        $currentMinor -ne $minor) {
        $buildRevision = 0
    }
    else {
        $buildRevision++
    }

    $scriptVersionObject = [PSCustomObject]@{
        Major         = $major
        Minor         = $minor
        BuildRevision = $buildRevision
    }

    Write-Host("New Script Version: v{0}.{1}.{2}" -f $major, $minor, $buildRevision)

    return $scriptVersionObject 
}
catch {
    throw 
}