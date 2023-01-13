# TCP/IP Settings Check

**Description:**

We validate if a `KeepAliveTime` DWORD value exists under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TcpIp\Parameters` and verify that it is set to a recommended value.

Exchange TCP `KeepAliveTime` registry entry should be set to a decimal value between 900000 and 1800000 (15 to 30 minutes in milliseconds). If there's no entry in the registry for `KeepAliveTime` then the default value is 2 hours.

This value, if not set correctly, can affect both connectivity and performance. You must make sure that the load balancer and any other devices in the path from client to Exchange are configured correctly.

The goal is to set Exchange with the lowest value so that client sessions, when ended, are ended by Exchange and not by the device.

Example:

`Client -> Firewall (1 hour) -> NLB (40 minutes) -> Exchange Servers (20 Minutes)`

**Included in HTML Report?**

Yes

**Additional resources:**

[Checklist for Troubleshooting Performance Related issues in Exchange 2013, 2016 and 2019 (on-prem)](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792)

