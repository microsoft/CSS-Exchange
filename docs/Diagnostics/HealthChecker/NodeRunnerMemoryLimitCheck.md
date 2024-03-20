# Noderunner.exe Memory Limit Check

### Description

This check is looking at the `<ExchangeInstallPath>\Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config` to look at the `memoryLimitMegabytes` value. This value should be set to 0 for the best performance. By having it set to 0, we do not limit the `noderunner.exe` processes. However, in some scenarios you might want to recommend to limit the process memory consumption to prevent server impact. If you do this, it is only recommended as a temporary fix.

### Included in HTML Report?

Yes

### Additional Resources

[Users can't receive email messages or connect to their mailbox](https://support.microsoft.com/topic/users-can-t-receive-email-messages-or-connect-to-their-mailbox-62d26d75-ae37-4308-b11a-878e9dc16d55)
