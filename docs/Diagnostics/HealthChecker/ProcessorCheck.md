# Number Of Processors

**Description:**

Number of Processors is the number of processor sockets detected on the server. It is only recommended to have up to 2 processors on the server. [3]

An additional note is displayed if `Type` is set to `VMware` and greater than 2 processors. [1]

#### How This Is Checked

```
([array](Get-WmiObject -Class Win32_Processor)).count
```

#### Number Of Logical and Physical Cores

Show the number of Physical and Logical cores presented to the OS. This is provided by the WmiObject class `Win32_Processor`.

- We show a warning if we have more than `24 Logical Cores` and running `Exchange 2013/2016` [2]
- We show a warning if we have more than `48 Logical Cores` and running `Exchange 2019` [2]

#### How This Is Checked

```
$processor = Get-WmiObject -Class Win32_Processor
$processor |ForEach-Object {$logical += $_.NumberOfLogicalProcessors; $physical += $_.NumberOfCores}
PS C:\> $logical
24
PS C:\> $physical
12
```

#### Max Processor Speed

Check to see what the Max Processor Speed is set to for the processor. If the processor is throttled which may be a result of a misconfigured Power Plan.

**NOTE:** If Power Plan isn't set to High Performance and the processor is being throttled, this will be flagged that Power Plan is the cause and to fix it ASAP.

#### How This Is Checked

```
$processor = Get-WmiObject -Class Win32_Processor
$throttled = $processor | Where-Object {$_.CurrentClockSpeed -lt $_.MaxClockSpeed}

if ($throttled) {
    Write-Host ("Throttling your CPU")
}

```

**Included in HTML Report?**

Yes

**Additional resources:**

[1 - Does CoresPerSocket Affect Performance?](https://blogs.vmware.com/vsphere/2013/10/does-CoresPerSocket-affect-performance.html)

[2 - Commodity servers](https://docs.microsoft.com/exchange/plan-and-deploy/deployment-ref/preferred-architecture-2019?view=exchserver-2019#commodity-servers)

[3 - Hardware requirements for Exchange 2019](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2019#hardware-requirements-for-exchange-2019)

[Exchange 2013 Sizing](https://docs.microsoft.com/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#exchange-2013-sizing)

[Hardware requirements for Exchange 2016](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2016#hardware-requirements-for-exchange-2016)

