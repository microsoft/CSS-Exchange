# AD Site Count Check

In large environments that contains a lot of sites, can cause a performance issue with Exchange. In particular Autodiscover app pool will peg the CPU at 4-hour intervals when there are many AD sites.

It is recommended to reduce the number of AD Sites within the environment to address this issue. However, there is a workaround that would prevent the issue from occurring every 4-hours and just every 24-hours.

In the `%ExchangeInstallPath%\Bin\Microsoft.Exchange.Directory.TopologyService.exe.config` file, change the `ExchangeTopologyCacheLifetime` value to be `1.00:00:00,00:20:00` instead to have the cache lifetime increase from 4-hours to 24-hours. It is not recommended to go beyond 24-hours.


**Included in HTML Report?**

Yes

**Additional resources:**

[Original Issue](https://github.com/microsoft/CSS-Exchange/issues/909)
