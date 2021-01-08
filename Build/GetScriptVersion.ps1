$webRequest = Invoke-WebRequest https://api.github.com/repos/dpaulson45/ExchangeLogCollector/releases
$json = ConvertFrom-Json -InputObject $webRequest.Content
$tagString = $json[0].tag_name
$split = $tagString.Split(".")
$oldMajor = [double]$split[0].Replace("v","")
$oldMinor = [double]$split[1]
$buildRevision = [double]$split[2]

$content = Get-Content .\Version.txt
$split = $content.Split(".")
$major = $split[0]
$minor = $split[1]

if($oldMajor -ne $major -or
$oldMinor -ne $minor)
{
  $buildRevision = 0
}
else
{
  $buildRevision++
}

$returnObject = [PSCustomObject]@{
    Major = $major
    Minor = $minor
    BuildRevision = $buildRevision
}

Write-Host("New Script Version: v{0}.{1}.{2}" -f $major, $minor, $buildRevision)

return $returnObject