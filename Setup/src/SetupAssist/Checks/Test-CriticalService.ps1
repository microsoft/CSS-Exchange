Function Test-CriticalService {
    $critical = @("MpsSvc")
    $services = Get-Service -ErrorAction SilentlyContinue

    foreach ($name in $critical) {
        $service = $services | Where-Object { $_.Name -eq $name }

        if ($null -ne $service) {

            if ($service.Status.ToString() -ne "Running" -or
                $service.StartType.ToString() -eq "Disabled") {
                "Critical Service '$name' Status: $($service.Status) StartType: $($service.StartType). Must be running and not disabled." | Receive-Output -IsWarning
            }
        }
    }
}