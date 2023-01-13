# IPv6 Enabled Check

**Description:**

We check if IPv6 is enabled or not. If we determine that IPv6 has been disabled, we check to see if it's fully disabled as recommended. We determine if the IPv6 is fully disabled by checking to see if we have an IPv6 Address available on the NIC and that it matches what is found in the registry at `SYSTEM\CurrentControlSet\Services\TcpIp6\Parameters\DisabledComponents`.

If both places don't have IPv6 enabled/disabled properly a warning is thrown. This can cause communication issues if not properly disabled.

**Included in HTML Report?**

Yes

**Additional resources:**

[Disabling IPv6 And Exchange – Going All The Way](https://blog.rmilne.ca/2014/10/29/disabling-ipv6-and-exchange-going-all-the-way/)

[Guidance for configuring IPv6 in Windows for advanced users](https://support.microsoft.com/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users)

