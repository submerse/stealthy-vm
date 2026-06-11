Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Acpi2 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetSystemFirmwareTable(uint Sig, uint ID, IntPtr buf, uint sz);
}
"@

# Provider = 'ACPI' = 0x41435049  (fixed)
# Table    = 'DSDT' reversed = 0x54445344
$sz = [Acpi2]::GetSystemFirmwareTable(0x41435049, 0x54445344, [IntPtr]::Zero, 0)
Write-Host "Required size: $sz bytes"

$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sz)
[Acpi2]::GetSystemFirmwareTable(0x41435049, 0x54445344, $ptr, $sz)
$bytes = New-Object byte[] $sz
[System.Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $sz)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
[IO.File]::WriteAllBytes("$env:TEMP\DSDT.dat", $bytes)
Write-Host "Saved to $env:TEMP\DSDT.dat"
