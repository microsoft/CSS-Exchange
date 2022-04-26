# Sleepy NIC Check

**Description:**

We validate the NIC power saving options. It's recommended to disable NIC power saving options as this may cause packet loss.

To detect the NIC power saving options, we're probing the sub keys under: `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}`

We then check if the `PnPCapabilities` REG_DWORD exists and if it does, we're validating its value. If it's `24` or `280`, NIC power saving is disabled as we recommend it.

We skip this check for `Multiplexor NIC adapters` and in case that the host system is `Hyper-V` (because we're assuming that we don't support NIC power saving options on this platform).

**NOTE:** If the REG_DWORD doesn't exists, we're assuming that NIC power saving is not disabled or configured and show a warning.

**Included in HTML Report?**

Yes

**Additional resources:**

[Information about power management setting on a network adapter](https://support.microsoft.com/kb/2740020)

