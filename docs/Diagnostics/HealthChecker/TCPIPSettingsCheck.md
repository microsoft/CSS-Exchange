# TCP/IP Settings Check

**Description:**

We validate if a `KeepAliveTime` DWORD value exists under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters` and verify that it is set to a recommended value.

Exchange TCP `KeepAliveTime` should be set to 30 minutes or no less than 15 minutes. If there's no entry in the registry for `KeepAliveTime` then the value is 2 hours. This value, if not set correctly, can affect both connectivity and performance. You must make sure that the load balancer and any other devices in the path from client to Exchange be set correctly.

The goal is to set Exchange with the lowest value so that client sessions when ended, are ended by the Exchange and not by a device.

Example:

`Client -> Firewall (1 hour) -> NLB (40 minutes) -> Exchange Servers (20 Minutes)`

**Included in HTML Report?**

Yes

**Additional resources:**

[Checklist for Troubleshooting Performance Related issues in Exchange 2013, 2016 and 2019 (on-prem)](https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Checklist-for-troubleshooting-Outlook-connectivity-in-Exchange/ba-p/604792)