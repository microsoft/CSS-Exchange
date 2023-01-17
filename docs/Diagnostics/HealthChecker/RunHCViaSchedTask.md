# How to run the Exchange Health Checker via Scheduled Task

**Description:**

You can run the Exchange Health Checker script by the help of a Scheduled Task on a daily, weekly or monthly base.

This article describes some of the ways how to run the script as task and how to create those tasks.

**Note:** We assume that the script is stored under `C:\Scripts\HealthChecker`. Please make sure to adjust the path if you use a different one in your environment.

1. The first thing to do is to create a service account which is used to run the script. It is recommended to use a strong password which will be changed regularly. It's also recommended to add the user to the `View-Only Organization Management` instead of `Organization Management`. This should be sufficient for the script to run.

**Note:** Using `View-Only Organization Management` instead of `Organization Management` requires you to add the account to the local `Administrators` group on each server. This can be achieved by creating a dedicated `Security Group` which is then added to the `Administrators` group on each Exchange server (manually or via `Group Policy`).

2. Now it's time to create the Scheduled Task. This can be done by the help of PowerShell:

We need to create multiple objects and finally combining them to the Scheduled Task. We need a `trigger`, `settings`, `action` and `task` object.

- Create a trigger that defines when the script should be executed:
    - (Example) Daily at 3 AM:
        - `$hcTrigger = New-ScheduledTaskTrigger -Daily -At 3am`
    - (Example) Every four weeks on Monday at 3 AM:
        - `$hcTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Monday -At 3am`

- Create a Scheduled Task setting object:
    - (Example) Create a Scheduled Task settings object using the default settings:
        - `$hcSettings = New-ScheduledTaskSettingsSet`
    - (Example) Create a Scheduled Task settings object and define `RestartCount` and `RestartInterval`:
        - `$hcSettings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 60)`

- Define the actions to be executed via Scheduled Task:
    - (Example) Update the HealthChecker script, execute the script against the local server and generate the HTML report:
        - `$hcAction = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory "C:\Scripts\HealthChecker\" -Argument '-NonInteractive -NoLogo -NoProfile -Command ".\HealthChecker.ps1 -ScriptUpdateOnly; .\HealthChecker.ps1; .\HealthChecker.ps1 -BuildHtmlServersReport"'`
    - (Example) Run the HealthChecker script against a remote Exchange server (named `ExchSrv01` in this example):
        - `$hcAction = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory "C:\Scripts\HealthChecker\" -Argument '-NonInteractive -NoLogo -NoProfile -Command ".\HealthChecker.ps1 -ScriptUpdateOnly; .\HealthChecker.ps1 -Server ExchSrv01; .\HealthChecker.ps1 -BuildHtmlServersReport"'`

- Create the Scheduled Task object using the pre-defined action, trigger and settings objects:
    - `$hcTask = New-ScheduledTask -Action $hcAction -Trigger $hcTrigger -Settings $hcSettings`

- Create the Scheduled Task:
    - `Register-ScheduledTask -TaskName 'HealthChecker Daily Run' -InputObject $hcTask -User (Read-Host "Please enter username in format (Domain\Username)") -Password (Read-Host "Please enter password")`

**Additional resources:**

[New-ScheduledTaskTrigger](https://docs.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2022-ps)

[New-ScheduledTaskSettingsSet](https://docs.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasksettingsset?view=windowsserver2022-ps)

[New-ScheduledTaskAction](https://docs.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskaction?view=windowsserver2022-ps)

[New-ScheduledTask](https://docs.microsoft.com/powershell/module/scheduledtasks/new-scheduledtask?view=windowsserver2022-ps)

[Register-ScheduledTask](https://docs.microsoft.com/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2022-ps)
