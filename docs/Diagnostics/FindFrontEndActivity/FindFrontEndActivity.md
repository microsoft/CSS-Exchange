# FindFrontEndActivity

Download the latest release: [FindFrontEndActivity.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/FindFrontEndActivity.ps1)

## Synopsis

Find HttpProxy protocol activity for one or more users.

## Syntax

    .\FindFrontEndActivity.ps1 -ServerName <String[]> -SamAccountName <String[]> [-LatencyThreshold <Int32>] [-Protocol <String[]>] [-IncludeNonExecutes] [-Quiet] [-TimeSpan <TimeSpan>] [<CommonParameters>]

    .\FindFrontEndActivity.ps1 -ServerName <String[]> -SamAccountName <String[]> [-LatencyThreshold <Int32>] [-Protocol <String[]>] [-IncludeNonExecutes] [-Quiet] -StartTime <DateTime> -EndTime <DateTime> [<CommonParameters>]

## Quick Start Examples

```powershell
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" | ft

DateTime                 AuthenticatedUser  UrlStem       ServerHostName TargetServer         TotalRequestTime
--------                 -----------------  -------       -------------- ------------         ----------------
2023-02-11T15:59:35.174Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  2214
```

```powershell
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" -LatencyThreshold 100 | ft

DateTime                 AuthenticatedUser  UrlStem       ServerHostName TargetServer         TotalRequestTime
--------                 -----------------  -------       -------------- ------------         ----------------
2023-02-11T15:59:29.898Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  505
2023-02-11T15:59:31.560Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  403
2023-02-11T15:59:35.174Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  2214
2023-02-11T15:59:35.488Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  161
2023-02-11T15:59:38.133Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  399
```

```powershell
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" -Protocol "ews", "mapi" | ft

DateTime                 AuthenticatedUser  UrlStem            ServerHostName TargetServer         TotalRequestTime
--------                 -----------------  -------            -------------- ------------         ----------------
2023-02-11T15:10:10.643Z contoso\john.doe   /EWS/Exchange.asmx EXCH1          exch1.contoso.local  1800019
2023-02-11T15:40:44.254Z contoso\john.doe   /EWS/Exchange.asmx EXCH1          exch1.contoso.local  1800028
2023-02-11T15:59:35.174Z contoso\john.doe   /mapi/emsmdb/      EXCH1          exch1.contoso.local  2214
```

Note the difference between -Quiet mode and the default:

```powershell
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" -Quiet
EXCH1
EXCH3
[PS] C:\>
[PS] C:\># Notice how we returned two servers when using -Quiet.
[PS] C:\>
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" | ft

DateTime                 AuthenticatedUser  UrlStem       ServerHostName TargetServer         TotalRequestTime
--------                 -----------------  -------       -------------- ------------         ----------------
2023-02-11T16:25:14.508Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  1182


[PS] C:\># But only one in the default mode. This is because the default is intended
[PS] C:\># to look for calls that are slow and are Execute calls. To see everything,
[PS] C:\># we need to remove the latency filter and include non-execute activity,
[PS] C:\># but this will return a lot of noise.
[PS] C:\>
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" -LatencyThreshold 0 -IncludeNonExecutes | ft

DateTime                 AuthenticatedUser  UrlStem       ServerHostName TargetServer         TotalRequestTime
--------                 -----------------  -------       -------------- ------------         ----------------
2023-02-11T16:00:07.619Z contoso\john.doe   /mapi/emsmdb/ EXCH3          exch1.contoso.local  17
2023-02-11T16:01:10.555Z contoso\john.doe   /mapi/nspi/   EXCH1          exch1.contoso.local  22
2023-02-11T16:05:11.132Z contoso\john.doe   /mapi/emsmdb/ EXCH1          exch1.contoso.local  659066
2023-02-11T16:05:12.101Z contoso\john.doe   /mapi/nspi/   EXCH1          exch1.contoso.local  21
...
```

To see all details, use `fl *`:

```powershell
[PS] C:\>Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "john.doe" | fl *


DateTime                        : 2023-02-11T16:25:14.508Z
RequestId                       : 0aa7958e-c59a-4f0a-903f-ebbd6ed93c9a
MajorVersion                    : 15
MinorVersion                    : 2
BuildVersion                    : 1118
...
```

## Description

When an Exchange client experiences issues, the HttpProxy logs are often the starting
point for determining whether the issue is with the client, the network, or the server.
However, since an Exchange environment may have dozens of front-end servers, it can be
difficult to find the relevant logs for a given user.

This script is designed to search the logs of all Exchange servers in parallel to quickly
find the HttpProxy logs related to specified users.

The default mode of the script is intended for finding slow MAPI calls from Outlook
clients. The `-Protocol` switch can be used to search more protocols, while specifying
`-LatencyThreshold` allows the admin to filter more aggressively or remove the
latency filter entirely. Running in `-Quiet` mode skips the filtering and just reports
any servers that have the specified users in the HttpProxy logs for the specified
protocols. See the parameters and examples for more information.

## Parameters

    -ServerName <String[]>
        The name of one or more Exchange servers to search. An easy way to search all Exchange
        servers in the forest is to simply pipe Get-ExchangeServer to the script.

        Required?                    true
        Position?                    named
        Default value
        Accept pipeline input?       true (ByValue, ByPropertyName)
        Accept wildcard characters?  false

    -SamAccountName <String[]>
        The samAccountNames of one or more users to search for.

        Required?                    true
        Position?                    named
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -LatencyThreshold <Int32>
        The minimum latency (in milliseconds) to search for. This is useful for filtering out
        noise from the logs. (Default: 1000). This parameter has no effect when -Quiet is used.

        Required?                    false
        Position?                    named
        Default value                1000
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Protocol <String[]>
        The protocols to search. Valid values are: Autodiscover, EAS, ECP, EWS, MAPI, OWA, PowerShell,
        RpcHttp. (Default: MAPI)

        Required?                    false
        Position?                    named
        Default value                @('MAPI')
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -IncludeNonExecutes [<SwitchParameter>]
        By default, NotificationWaits from the MAPI logs are not included, because these are slow
        by design. Specify this switch to include them.

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Quiet [<SwitchParameter>]
        This switch causes the script to only report the server names rather than the full log
        entries. This may be somewhat faster. However, there is no filtering for LatencyThreshold
        and NotificationWait when this option is used.

        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -TimeSpan <TimeSpan>
        Specify how far back to search the logs. This is a TimeSpan value, such as "01:00" for the
        last hour or "00:30" for the last 30 minutes. (Default: 15 minutes). Use this parameter to
        search the most recent logs. Use StartTime and EndTime to search older logs.

        Required?                    false
        Position?                    named
        Default value                (New-TimeSpan -Minutes 15)
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -StartTime <DateTime>
        Logs older than this time are not searched. This is a DateTime value, such as (Get-Date).AddDays(-1)
        or "2023-02-11 08:00". Use this parameter to search old logs. Use -TimeSpan to search the
        most recent logs.

        Required?                    true
        Position?                    named
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -EndTime <DateTime>
        Logs newer than this time are not searched. This is a DateTime value, such as (Get-Date).AddDays(-1)
        or "2023-02-11 09:00". Use this parameter to search old logs. Use -TimeSpan to search the
        most recent logs.

        Required?                    true
        Position?                    named
        Default value
        Accept pipeline input?       false
        Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https://go.microsoft.com/fwlink/?LinkID=113216).

## Example 1

```powershell
Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" | ft
```
Show any MAPI HttpProxy activity that took more than 1 second for user1 or user2 within the last 15 minutes on all Exchange servers in the forest.

## Example 2

```powershell
Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" -Quiet
```
Show only the server names where user1 or user2 are found in the MAPI HttpProxy logs within the last 15 minutes.

## Example 3

```powershell
Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" -Protocol "ews", "mapi" -LatencyThreshold 100 -TimeSpan "00:30"
```
Show any EWS or MAPI HttpProxy activity that took more than 100 milliseconds for user1 or user2 within the last 30 minutes on all Exchange servers in the forest.
