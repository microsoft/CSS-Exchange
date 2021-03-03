#Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.

function Check-26855()
{
    Write-Host "Checking for CVE-2021-26855 in the HttpProxy logs"
    $csv = Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName -ErrorAction SilentlyContinue | Where-Object {  $_.AnchorMailbox -like 'ServerInfo~*/*' }
    if($csv.Length -gt 0)
    {
        Write-Host "Suspicious entries found in $env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy.  Check the .\CVE-2021-26855.csv log for specific entries." -ForegroundColor Yellow
        if (Test-Path ".\CVE-2021-26855.log")
        {
            del .\CVE-2021-26855.log -Force
        }
        $csv | Out-File .\CVE-2021-26855.log -Append
    }
    else
    {
        Write-Host "No suspicious entries found." -ForegroundColor Green
    }
}

function Check-26858()
{
    Write-Host "`r`nChecking for CVE-2021-26858 in the OABGenerator logs"
    $logs = Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select Path
    if($logs.Path.Count -gt 0)
    {
        Write-Host "Suspicious OAB download entries found in the following logs, please review them for `"Download failed and temporary file`" entries:" -ForegroundColor Yellow
        $logs.Path
    }
    else
    {
        Write-Host "No suspicious entries found." -ForegroundColor Green
    }
}

function Check-26857()
{
    Write-Host "`r`nChecking for CVE-2021-26857 in the Event Logs"
    $eventLogs = Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*System.InvalidCastException*" }
    if($eventLogs.Count -gt 0)
    {
        Write-Host "Suspicious event log entries for Source `"MSExchange Unified Messaging`" and Message `"System.InvalidCastException`" were found.  These may indicate exploitation.  Please review these event log entries for more details." -ForegroundColor Yellow
    }
    else
    {
        Write-Host "No suspicious entries found." -ForegroundColor Green
    }
}

function Check-27065()
{
    Write-Host "`r`nChecking for CVE-2021-26857 in the ECP Logs"
    $logs = Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" | Select-String "Set-.*VirtualDirectory" -List | Select Path
    if($logs.Path.Count -gt 0)
    {
        Write-Host "Suspicious virtual directory modifications found in the following logs, please review them for `"Set-*VirtualDirectory`" entries:" -ForegroundColor Yellow
        $logs.Path
    }
    else
    {
        Write-Host "No suspicious entries found." -ForegroundColor Green
    }
}

function Check-SuspiciousFiles()
{
    Write-Host "`r`nChecking for suspicious files"
    $lsassFiles = Get-ChildItem -Recurse -Path "$env:WINDIR\temp\lsass.*dmp"
    $lsassFiles += Get-ChildItem -Recurse -Path "c:\root\lsass.*dmp"
    if($lsassFiles.Count -gt 0)
    {
        Write-Host "lsass.exe dumps found, please verify these are expected:" -ForegroundColor Yellow
        $lsassFiles.FullName
    }
    else
    {
        Write-Host "No suspicious lsass dumps found." -ForegroundColor Green
    }

    $zipFiles = Get-ChildItem -Recurse -Path "$env:ProgramData" -Include *.7z,*.zip,*.rar -ErrorAction SilentlyContinue
    if($zipFiles.Count -gt 0)
    {
        Write-Host "`r`nZipped files found in $env:ProgramData, please verify these are expected:" -ForegroundColor Yellow
        $zipFiles.FullName
    }
    else
    {
        Write-Host "`r`nNo suspicious zip files found." -ForegroundColor Green
    }
}

Write-Host "This script checks for exploits using the instructions outlined in https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers`r`n"
Check-26855
Check-26858
Check-26857
Check-27065
Check-SuspiciousFiles