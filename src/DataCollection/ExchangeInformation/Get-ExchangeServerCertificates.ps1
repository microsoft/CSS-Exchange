Function Get-ExchangeServerCertificates {

    Write-VerboseOutput("Calling: Get-ExchangeServerCertificates")

    try {
        Write-VerboseOutput("Trying to receive certificates from Exchange server: {0}" -f $Script:Server)
        $exchangeServerCertificates = Get-ExchangeCertificate -Server $Script:Server -ErrorAction Stop

        if ($null -ne $exchangeServerCertificates) {
            try {
                $authConfig = Get-AuthConfig -ErrorAction Stop
                $authConfigDetected = $true
            } catch {
                $authConfigDetected = $false
                Invoke-CatchActions
            }

            [array]$certObject = @()
            foreach ($cert in $exchangeServerCertificates) {
                try {
                    $certificateLifetime = ([DateTime]($cert.NotAfter) - (Get-Date)).Days
                    $sanCertificateInfo = $false

                    if ($null -ne $cert.DnsNameList -and
                        ($cert.DnsNameList).Count -gt 1) {
                        $sanCertificateInfo = $true
                    }

                    if ($authConfigDetected) {
                        $isAuthConfigInfo = $false

                        if ($cert.Thumbprint -eq $authConfig.CurrentCertificateThumbprint) {
                            $isAuthConfigInfo = $true
                        }
                    } else {
                        $isAuthConfigInfo = "InvalidAuthConfig"
                    }

                    $certInformationObj = New-Object PSCustomObject
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $cert.FriendlyName
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value $cert.Thumbprint
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "PublicKeySize" -Value $cert.PublicKeySize
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "IsSanCertificate" -Value $sanCertificateInfo
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Namespaces" -Value $cert.DnsNameList
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Services" -Value $cert.Services
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "IsCurrentAuthConfigCertificate" -Value $isAuthConfigInfo
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "LifetimeInDays" -Value $certificateLifetime
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $cert.Status
                    $certInformationObj | Add-Member -MemberType NoteProperty -Name "CertificateObject" -Value $cert

                    $certObject += $certInformationObj
                } catch {
                    Write-VerboseOutput("Unable to process certificate: {0}" -f $cert.Thumbprint)
                    Invoke-CatchActions
                }
            }
            Write-VerboseOutput("Processed: {0} certificates" -f $certObject.Count)
            return $certObject
        } else {
            Write-VerboseOutput("Failed to find any Exchange certificates")
            return $null
        }
    } catch {
        Write-VerboseWriter("Failed to run Get-ExchangeCertificate. Error: {0}." -f $Error[0].Exception)
        Invoke-CatchActions
    }
}