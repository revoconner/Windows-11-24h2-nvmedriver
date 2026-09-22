# Windows-11-24h2-nvmedriver
It enables the nvmedrive.sys to work on Windows 11 24H2 26100.8875 and above, on builds where Microsoft blocked the driver being enabled.

To enable the driver, make sure the actual drivers are present, and then run this:
`reg add "HKLM\SYSTEM\CurrentControlSet\Enum\INSTANCE\Device Parameters\StorPort" /v EnableNVMeInterface /t REG_DWORD /d 1 /f`

**The repo includes helper scripts for debugging**

## Read the details here
[Full blog post](https://revoconner.com/writing/windows-nvme-driver-workaround)

### Please read the blog post. Do not do this if you are unsure, if might make the system unbootable.
