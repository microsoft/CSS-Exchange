#Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.

function Test-ExchangeHafnium {
<#
	.SYNOPSIS
		Checks targeted exchange servers for signs of Hafnium vulnerability compromise.
	
	.DESCRIPTION
		Checks targeted exchange servers for signs of Hafnium vulnerability compromise.
		Will do so in parallel if more than one server is specified, so long as names aren't provided by pipeline.
	
		The vulnerabilities are described in CVE-2021-26855, 26858, 26857, and 27065
	
	.PARAMETER ComputerName
		The list of server names to scan for signs of compromise.
		Do not provide these by pipeline if you want parallel processing.
	
	.PARAMETER Credential
		Credentials to use for remote connections.
	
	.EXAMPLE
		PS C:\> Test-ExchangeHafnium
	
		Scans the current computer for signs of Hafnium vulnerability compromise.
	
	.EXAMPLE
		PS C:\> Test-ExchangeHafnium -ComputerName (Get-ExchangeServer).Fqdn
	
		Scans all exchange servers in the organization for Hafnium vulnerability compromises
#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$ComputerName = $env:COMPUTERNAME,
		
		[pscredential]
		$Credential
	)
	begin {
		#region Remoting Scriptblock
		$scriptBlock = {
			#region Functions
			function Get-Cve26855 {
				[CmdletBinding()]
				param ()
				
				$exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
				
				foreach ($httpProxyLogfile in Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy" -Filter '*.log') {
					Import-Csv -Path $httpProxyLogfile.FullName | Where-Object AnchorMailbox -Like 'ServerInfo~*/*' | Select-Object -Property DateTime, AnchorMailbox
				}
			}
			
			function Get-Cve26857 {
				[CmdletBinding()]
				param ()
				
				Get-WinEvent -FilterHashtable @{
					LogName	     = 'Application'
					ProviderName = 'MSExchange Unified Messaging'
					Level	     = '2'
				} -ErrorAction SilentlyContinue | Where-Object Message -like "*System.InvalidCastException*"
			}
			
			function Get-Cve26858 {
				[CmdletBinding()]
				param ()
				
				$exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
				
				Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path
			}
			
			function Get-Cve27065 {
				[CmdletBinding()]
				param ()
				
				$exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
				
				Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" | Select-String "Set-.*VirtualDirectory" -List | Select-Object -ExpandProperty Path
			}
			
			function Get-SuspiciousFile {
				[CmdletBinding()]
				param ()
				
				foreach ($file in Get-ChildItem -Recurse -Path "$env:WINDIR\temp\lsass.*dmp") {
					[PSCustomObject]@{
						ComputerName = $env:COMPUTERNAME
						Type		 = 'LsassDump'
						Path		 = $file.FullName
						Name		 = $file.Name
					}
				}
				foreach ($file in Get-ChildItem -Recurse -Path "c:\root\lsass.*dmp") {
					[PSCustomObject]@{
						ComputerName = $env:COMPUTERNAME
						Type		 = 'LsassDump'
						Path		 = $file.FullName
						Name		 = $file.Name
					}
				}
				foreach ($file in Get-ChildItem -Recurse -Path $env:ProgramData -ErrorAction SilentlyContinue | Where-Object Extension -match ".7z|.zip|.rar") {
					[PSCustomObject]@{
						ComputerName = $env:COMPUTERNAME
						Type		 = 'SuspiciousArchive'
						Path		 = $file.FullName
						Name		 = $file.Name
					}
				}
			}
			#endregion Functions
			
			[PSCustomObject]@{
				ComputerName = $env:COMPUTERNAME
				Cve26855	 = Get-Cve26855
				Cve26857	 = Get-Cve26857
				Cve26858	 = Get-Cve26858
				Cve27065	 = Get-Cve27065
				Suspicious   = Get-SuspiciousFile
			}
		}
		#endregion Remoting Scriptblock
		$parameters = @{
			ScriptBlock = $scriptBlock
		}
		if ($Credential) { $parameters.Credential = $Credential }
	}
	process {
		Invoke-Command @parameters -ComputerName $ComputerName
	}
}

function Write-HafniumReport {
<#
	.SYNOPSIS
		Processes output of Test-ExchangeHafnium for reporting on the console screen.
	
	.DESCRIPTION
		Processes output of Test-ExchangeHafnium for reporting on the console screen.
	
	.PARAMETER InputObject
		The reports provided by Test-ExchangeHafnium
	
	.PARAMETER OutPath
		Path to a FOLDER in which to generate output logfiles.
		This command will only write to the console screen if no path is provided.
	
	.EXAMPLE
		PS C:\> Test-ExchangeHafnium -ComputerName (Get-ExchangeServer).Fqdn | Write-HafniumReport -OutPath C:\logs
	
		Gather data from all exchange servers in the organization and write a report to C:\logs
#>
	[CmdletBinding()]
	param (
		[parameter(ValueFromPipeline = $true)]
		$InputObject,
		
		[string]
		$OutPath
	)
	
	process {
		foreach ($report in $InputObject) {
			Write-Host "Hafnium Status: Exchange Server $($report.ComputerName)"
			if (-not ($report.Cve26855 -or $report.Cve26857 -or $report.Cve26858 -or $report.Cve27065 -or $report.Suspicious)) {
				Write-Host "  Nothing suspicious detected" -ForegroundColor Green
				Write-Host ""
				continue
			}
			
			if ($report.Cve26855) {
				Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
				if ($OutPath) {
					$newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
					$report.Cve26855 | Export-Csv -Path $newFile
					Write-Host "  Report exported to: $newFile"
				}
				else {
					$report.Cve26855 | Format-Table -AutoSize | Out-Host
				}
				Write-Host ""
			}
			if ($report.Cve26857) {
				Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
				Write-Host "  $(@($report.Cve26857).Count) events found"
				if ($OutPath) {
					$newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
					$report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
					Write-Host "  Report exported to: $newFile"
				}
				Write-Host ""
			}
			if ($report.Cve26858) {
				Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
				Write-Host "  Please review the following files for 'Download failed and temporary file' entries:"
				foreach ($entry in $report.Cve26858) {
					Write-Host "   $entry"
				}
				if ($OutPath) {
					$newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
					$report.Cve26858 | Set-Content -Path $newFile
					Write-Host "  Report exported to: $newFile"
				}
				Write-Host ""
			}
			if ($report.Suspicious) {
				Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
				if ($OutPath) {
					$newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
					$report.Suspicious | Export-Csv -Path $newFile
					Write-Host "  Report exported to: $newFile"
				}
				else {
					foreach ($entry in $report.Suspicious) {
						Write-Host "   $($entry.Type) : $($entry.Path)"
					}
				}
			}
		}
	}
}
