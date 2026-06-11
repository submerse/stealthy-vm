#Requires -RunAsAdministrator
<#
.SYNOPSIS
    VM detection audit for KVM/QEMU hardening - run as Admin inside Windows guest.
    Reports CPUID hypervisor leaves, suspicious PCI devices, registry traces, processes.
#>

# --- CPUID via runtime-compiled shellcode -------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Cpuid {
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);
    [DllImport("kernel32.dll")] static extern bool   VirtualFree(IntPtr a,UIntPtr s,uint t);
    [DllImport("kernel32.dll")] static extern bool   VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void Fn(IntPtr r, uint leaf, uint sub);

    // x64 stub: (IntPtr result, uint leaf, uint subleaf)
    //   push rbx / push rcx
    //   mov eax,edx  ; leaf
    //   mov ecx,r8d  ; subleaf
    //   cpuid
    //   pop r10      ; restore result ptr
    //   mov [r10],eax ; mov [r10+4],ebx ; mov [r10+8],ecx ; mov [r10+12],edx
    //   pop rbx / ret
    static readonly byte[] code = {
        0x53,0x51,0x8B,0xC2,0x41,0x8B,0xC8,0x0F,0xA2,
        0x41,0x5A,
        0x41,0x89,0x02,
        0x41,0x89,0x5A,0x04,
        0x41,0x89,0x4A,0x08,
        0x41,0x89,0x52,0x0C,
        0x5B,0xC3
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct R { public uint eax,ebx,ecx,edx; }

    public static R Query(uint leaf, uint sub=0) {
        IntPtr m = VirtualAlloc(IntPtr.Zero, new UIntPtr((uint)code.Length), 0x3000, 0x04);
        Marshal.Copy(code, 0, m, code.Length);
        uint d; VirtualProtect(m, new UIntPtr((uint)code.Length), 0x20, out d);
        var fn = (Fn)Marshal.GetDelegateForFunctionPointer(m, typeof(Fn));
        var r = new R();
        IntPtr p = Marshal.AllocHGlobal(16);
        Marshal.StructureToPtr(r, p, false);
        fn(p, leaf, sub);
        r = (R)Marshal.PtrToStructure(p, typeof(R));
        Marshal.FreeHGlobal(p);
        VirtualFree(m, UIntPtr.Zero, 0x8000);
        return r;
    }
    public static string EbxEcxEdxStr(R r) {
        var b = new byte[12];
        BitConverter.GetBytes(r.ebx).CopyTo(b,0);
        BitConverter.GetBytes(r.ecx).CopyTo(b,4);
        BitConverter.GetBytes(r.edx).CopyTo(b,8);
        return System.Text.Encoding.ASCII.GetString(b);
    }
}
'@ -Language CSharp -ErrorAction Stop

function Write-OK   { param($m) Write-Host "[  OK  ] $m" -ForegroundColor Green  }
function Write-WARN { param($m) Write-Host "[ WARN ] $m" -ForegroundColor Yellow }
function Write-FAIL { param($m) Write-Host "[ FAIL ] $m" -ForegroundColor Red    }
function Write-INFO { param($m) Write-Host "[ INFO ] $m" -ForegroundColor Cyan   }

Write-Host ""
Write-Host "==========================================" -ForegroundColor White
Write-Host "    VM DETECTION AUDIT - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor White
Write-Host ""

# --- 1. CPUID hypervisor checks ----------------------------------------------
Write-Host "[ CPUID HYPERVISOR CHECKS ]" -ForegroundColor White

# Leaf 1 - ECX bit 31
$l1 = [Cpuid]::Query(1, 0)
$hyperBit = ($l1.ecx -shr 31) -band 1
if ($hyperBit -eq 0) {
    Write-OK  "CPUID.1:ECX[31] = 0  (hypervisor present bit is CLEAR)"
} else {
    Write-FAIL "CPUID.1:ECX[31] = 1  (hypervisor present bit SET - detectable!)"
}

# Leaf 0x40000000 - hypervisor vendor
$l4 = [Cpuid]::Query(0x40000000, 0)
$vendor = [Cpuid]::EbxEcxEdxStr($l4)
$badVendors = @("KVMKVMKVM", "Microsoft HV", "VMwareVMware", "XenVMMXenVMM", "VBoxVBoxVBox")
$badFound = $false
foreach ($bv in $badVendors) {
    if ($vendor -like "*$bv*") { $badFound = $true; break }
}
Write-INFO "CPUID.0x40000000: EAX=$($l4.eax.ToString('X8'))  vendor='$($vendor.Trim([char]0))'"
if ($badFound) {
    Write-FAIL "Hypervisor vendor string '$vendor' is a known VM fingerprint!"
} elseif ($l4.eax -ge 0x40000000) {
    Write-WARN "EAX=0x$($l4.eax.ToString('X8')) >= 0x40000000 - hypervisor CPUID range is active"
} else {
    Write-OK  "No hypervisor vendor string exposed at leaf 0x40000000"
}

# Leaf 0x40000001 - KVM/HyperV feature flags
$l41 = [Cpuid]::Query(0x40000001, 0)
Write-INFO "CPUID.0x40000001: EAX=$($l41.eax.ToString('X8')) EBX=$($l41.ebx.ToString('X8')) ECX=$($l41.ecx.ToString('X8')) EDX=$($l41.edx.ToString('X8'))"
if ($l41.eax -ne 0 -or $l41.ebx -ne 0 -or $l41.ecx -ne 0 -or $l41.edx -ne 0) {
    Write-WARN "Leaf 0x40000001 returns non-zero data - possible hypervisor feature flags"
} else {
    Write-OK  "Leaf 0x40000001 returns all zeros"
}

# CPU basic info
$l0 = [Cpuid]::Query(0, 0)
$vid = [System.Text.Encoding]::ASCII.GetString(
    [BitConverter]::GetBytes($l0.ebx) +
    [BitConverter]::GetBytes($l0.edx) +
    [BitConverter]::GetBytes($l0.ecx))
Write-INFO "CPUID.0: max_leaf=$($l0.eax.ToString('X8'))  vendor='$vid'"

Write-Host ""

# --- 2. WMI HypervisorPresent -------------------------------------------------
Write-Host "[ WMI / OS HYPERVISOR FLAGS ]" -ForegroundColor White
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs) {
    if ($cs.HypervisorPresent -eq $true) {
        Write-FAIL "Win32_ComputerSystem.HypervisorPresent = True"
    } else {
        Write-OK  "Win32_ComputerSystem.HypervisorPresent = False"
    }
    Write-INFO "Manufacturer: $($cs.Manufacturer)  Model: $($cs.Model)"
}
Write-Host ""

# --- 3. PCI device fingerprint check -----------------------------------------
Write-Host "[ PCI DEVICE FINGERPRINTS ]" -ForegroundColor White
$suspectVIDs = @{
    '1B36' = 'QEMU PCI';
    '1AF4' = 'VirtIO / Red Hat';
    '5853' = 'Xen';
    '15AD' = 'VMware';
    '80EE' = 'VirtualBox';
}
# Also flag 1AF4 appearing as subsystem vendor (SUBSYS_xxxxxx1AF4)
$allPnp = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue
$foundSuspect = $false
foreach ($dev in $allPnp) {
    try {
        $hwids = (Get-PnpDeviceProperty -InputObject $dev -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data
        foreach ($id in $hwids) {
            foreach ($vid in $suspectVIDs.Keys) {
                if ($id -match "VEN_$vid") {
                    Write-FAIL "SUSPECT [$($suspectVIDs[$vid])]: $($dev.FriendlyName) - $id"
                    $foundSuspect = $true
                }
            }
            # Check subsystem vendor (last 4 hex digits of SUBSYS_XXXXXXXXVVVV)
            if ($id -match 'SUBSYS_[0-9A-F]{4}(1AF4|1B36|15AD|80EE)') {
                Write-FAIL "SUSPECT SUBSYS vendor [$($Matches[1])]: $($dev.FriendlyName) - $id"
                $foundSuspect = $true
            }
        }
    } catch {}
}
if (-not $foundSuspect) { Write-OK "No VirtIO/QEMU/Xen/VMware PCI or SUBSYS vendor IDs found" }

# Also list all VEN_ IDs briefly
Write-Info "All PCI vendor IDs visible:"
$allPnp | ForEach-Object {
    try {
        $hwids = (Get-PnpDeviceProperty -InputObject $_ -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data
        foreach ($id in $hwids) {
            if ($id -match 'VEN_([0-9A-F]{4})' -and $id -match 'DEV_') {
                "  $($_.FriendlyName):  $id"
                break
            }
        }
    } catch {}
} | Sort-Object | Get-Unique | ForEach-Object { Write-Host $_ }

Write-Host ""

# --- 4. Disk identifiers ------------------------------------------------------
Write-Host "[ DISK / STORAGE IDENTIFIERS ]" -ForegroundColor White
$disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
foreach ($d in $disks) {
    $model  = $d.Model
    $serial = $d.SerialNumber
    $badDisk = $false
    foreach ($kw in @('QEMU','VBOX','VIRT','VMWARE','HARDDISK')) {
        if ($model -match $kw) { $badDisk = $true }
    }
    if ($serial -match '^\s*$' -or $serial -eq $null) { $badDisk = $true; $serial = "(empty)" }
    if ($badDisk) {
        Write-FAIL "Disk: '$model'  serial='$serial'"
    } else {
        Write-OK  "Disk: '$model'  serial='$serial'"
    }
}
Write-Host ""

# --- 5. Registry VM traces ----------------------------------------------------
Write-Host "[ REGISTRY VM TRACES ]" -ForegroundColor White
$vmRegKeys = @(
    'HKLM:\SOFTWARE\QEMU',
    'HKLM:\SOFTWARE\Red Hat',
    'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
    'HKLM:\SOFTWARE\VMware, Inc.',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxMouse',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxSF',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxVideo',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vmci',
    'HKLM:\SYSTEM\CurrentControlSet\Services\qemu-ga',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VIOSTOR',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VIOSCSI',
    'HKLM:\SYSTEM\CurrentControlSet\Services\netkvm',
    'HKLM:\SYSTEM\CurrentControlSet\Services\balloon'
)
$foundReg = $false
$foundRegKeys = [System.Collections.Generic.List[string]]::new()
foreach ($k in $vmRegKeys) {
    if (Test-Path $k) {
        Write-FAIL "Registry key found: $k"
        $foundRegKeys.Add($k)
        $foundReg = $true
    }
}
# Check SYSTEM\MountedDevices for \DosDevices entries with QEMU strings
$scsiKey = 'HKLM:\HARDWARE\DEVICEMAP\Scsi'
if (Test-Path $scsiKey) {
    $scsiVal = reg query "HKLM\HARDWARE\DEVICEMAP\Scsi" /s 2>$null | Select-String -Pattern 'QEMU|qemu|VirtIO|virtio' -CaseSensitive:$false
    if ($scsiVal) { Write-FAIL "SCSI registry contains VM strings: $scsiVal"; $foundReg = $true }
}

if ($foundRegKeys.Count -gt 0) {
    Write-Host ""
    $choice = Read-Host "Delete $($foundRegKeys.Count) VM registry key(s) now? [y/N]"
    if ($choice -match '^[Yy]$') {
        foreach ($k in $foundRegKeys) {
            try {
                Remove-Item -Path $k -Recurse -Force -ErrorAction Stop
                Write-OK "  Deleted: $k"
            } catch {
                Write-FAIL "  Could not delete $k : $_"
            }
        }
    }
}
if (-not $foundReg) { Write-OK "No VM registry keys found" }
Write-Host ""

# --- 6. Running processes -----------------------------------------------------
Write-Host "[ VM-RELATED PROCESSES ]" -ForegroundColor White
$vmProcs = @('qemu-ga','vboxservice','vboxtray','vmtoolsd','vmwaretray',
             'vmwareuser','xenservice','spicesvc','spice-guest-tools')
$foundProc = $false
foreach ($pn in $vmProcs) {
    $p = Get-Process $pn -ErrorAction SilentlyContinue
    if ($p) { Write-FAIL "Process running: $pn (PID $($p.Id))"; $foundProc = $true }
}
if (-not $foundProc) { Write-OK "No VM guest agent processes found" }
Write-Host ""

# --- 7. SMBIOS / System info -------------------------------------------------
Write-Host "[ SMBIOS / SYSTEM INFO ]" -ForegroundColor White
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
Write-INFO "BIOS: Manufacturer='$($bios.Manufacturer)'  Version='$($bios.SMBIOSBIOSVersion)'  SerialNumber='$($bios.SerialNumber)'"
Write-INFO "Board: Manufacturer='$($board.Manufacturer)'  Product='$($board.Product)'  Serial='$($board.SerialNumber)'"
$badSMBIOS = $false
foreach ($kw in @('QEMU','BOCHS','VBOX','VMWARE','Seabios','Virtual','KVM')) {
    if ("$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion) $($board.Manufacturer) $($board.Product)" -match $kw) {
        Write-FAIL "SMBIOS contains VM keyword: '$kw'"
        $badSMBIOS = $true
    }
}
if (-not $badSMBIOS) { Write-OK "SMBIOS strings look clean" }
Write-Host ""

# --- 8. ACPI table OEM IDs (via GetSystemFirmwareTable) ----------------------
Write-Host "[ ACPI OEM IDs ]" -ForegroundColor White
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class AcpiCheck {
    [DllImport("kernel32.dll")] public static extern uint GetSystemFirmwareTable(uint prov,uint tbl,IntPtr buf,uint sz);
    public static byte[] GetTable(string sig) {
        byte[] s = System.Text.Encoding.ASCII.GetBytes(sig);
        Array.Reverse(s);
        uint fsig = BitConverter.ToUInt32(s,0);
        uint sz = GetSystemFirmwareTable(0x41435049,fsig,IntPtr.Zero,0);
        if(sz==0) return null;
        IntPtr p = Marshal.AllocHGlobal((int)sz);
        GetSystemFirmwareTable(0x41435049,fsig,p,sz);
        byte[] r = new byte[sz];
        Marshal.Copy(p,r,0,(int)sz);
        Marshal.FreeHGlobal(p);
        return r;
    }
    public static string Ascii(byte[]b,int off,int len){
        if(b==null||off+len>b.Length)return"";
        return System.Text.Encoding.ASCII.GetString(b,off,len).TrimEnd('\0',' ');
    }
}
'@ -Language CSharp -ErrorAction SilentlyContinue

$acpiTables = @('FACP','DSDT','SSDT','APIC','BGRT')
$badACPI = $false
foreach ($tbl in $acpiTables) {
    $data = [AcpiCheck]::GetTable($tbl)
    if ($data -ne $null -and $data.Length -ge 36) {
        $oemId    = [AcpiCheck]::Ascii($data, 10, 6)
        $oemTbl   = [AcpiCheck]::Ascii($data, 16, 8)
        $creator  = [AcpiCheck]::Ascii($data, 28, 4)
        Write-INFO "  $tbl : OEM='$oemId'  table='$oemTbl'  creator='$creator'"
        $tableStr = ([System.Text.Encoding]::ASCII.GetString($data)).ToUpper()
        foreach ($kw in @('QEMU','BOCHS','BXPC','VBOX','KVMKVMKVM')) {
            if ($tableStr.Contains($kw)) {
                Write-FAIL "  $tbl contains VM keyword: '$kw'"
                $badACPI = $true
            }
        }
    }
}
if (-not $badACPI) { Write-OK "No VM keywords found in checked ACPI tables" }
Write-Host ""

# --- 9. Vanguard artifact sweep + optional purge -----------------------------
Write-Host "[ VANGUARD ARTIFACT SWEEP ]" -ForegroundColor White

# Known Vanguard file paths and registry keys
$vgFilePaths = @(
    "$env:SystemRoot\System32\drivers\vgk.sys",
    "$env:SystemRoot\System32\drivers\vgc.sys",
    "C:\Program Files\Riot Vanguard",
    "C:\Program Files (x86)\Riot Vanguard",
    "$env:ProgramData\Riot Games",
    "$env:LOCALAPPDATA\Riot Games",
    "$env:APPDATA\Riot Games",
    "$env:LOCALAPPDATA\Programs\Riot Games",
    "C:\Riot Games"
)
$vgRegKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\vgk',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vgc',
    'HKLM:\SOFTWARE\Riot Games',
    'HKLM:\SOFTWARE\WOW6432Node\Riot Games',
    'HKCU:\SOFTWARE\Riot Games'
)

# Broad filesystem search for vgk.sys on all fixed drives (fast, depth-limited)
Write-Host "  Scanning all drives for vgk.sys / vgc.sys (may take a moment)..." -ForegroundColor DarkGray
$drives = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }).Root
$extraFound = @()
foreach ($drive in $drives) {
    try {
        $hits = Get-ChildItem -Path $drive -Recurse -Force -ErrorAction SilentlyContinue -Filter '*.sys' |
                Where-Object { $_.Name -in @('vgk.sys','vgc.sys') }
        foreach ($h in $hits) {
            if ($vgFilePaths -notcontains $h.FullName) { $extraFound += $h.FullName }
        }
    } catch {}
}

# Collect everything found
$foundItems = [System.Collections.Generic.List[string]]::new()

foreach ($p in $vgFilePaths) {
    if (Test-Path $p) { $foundItems.Add($p) }
}
foreach ($p in $extraFound) {
    if (-not $foundItems.Contains($p)) { $foundItems.Add($p) }
}
foreach ($k in $vgRegKeys) {
    if (Test-Path $k) { $foundItems.Add($k) }
}

if ($foundItems.Count -eq 0) {
    Write-OK "No Vanguard artifacts found - clean slate for fresh install"
} else {
    Write-WARN "Found $($foundItems.Count) Vanguard artifact(s):"
    foreach ($item in $foundItems) {
        Write-Host "    $item" -ForegroundColor Yellow
    }

    Write-Host ""
    $choice = Read-Host "Delete ALL listed artifacts? Vanguard service will be stopped first. [y/N]"
    if ($choice -match '^[Yy]$') {

        # Stop and delete vgk service if running
        foreach ($svc in @('vgk','vgc')) {
            $s = Get-Service $svc -ErrorAction SilentlyContinue
            if ($s) {
                Write-Host "  Stopping service: $svc" -ForegroundColor DarkGray
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800
                sc.exe delete $svc 2>$null | Out-Null
            }
        }

        foreach ($item in $foundItems) {
            if ($item.StartsWith('HK')) {
                # Registry key
                try {
                    Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
                    Write-OK "  Deleted registry: $item"
                } catch {
                    Write-FAIL "  Could not delete registry: $item  ($_)"
                }
            } else {
                # File or directory
                try {
                    # Take ownership and remove read-only / system flags before delete
                    if (Test-Path $item -PathType Container) {
                        & takeown /f $item /r /d y 2>$null | Out-Null
                        & icacls $item /grant "$($env:USERNAME):F" /t /c /q 2>$null | Out-Null
                        Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
                    } else {
                        & takeown /f $item 2>$null | Out-Null
                        & icacls $item /grant "$($env:USERNAME):F" /c /q 2>$null | Out-Null
                        Remove-Item -Path $item -Force -ErrorAction Stop
                    }
                    Write-OK "  Deleted: $item"
                } catch {
                    Write-FAIL "  Could not delete: $item  ($_)"
                }
            }
        }

        Write-Host ""
        Write-OK "Purge complete. You can now do a fresh Vanguard install."
        Write-WARN "Recommended: also clear Windows Event Log entries (optional):"
        Write-Host '    wevtutil cl System ; wevtutil cl Application' -ForegroundColor DarkGray

    } else {
        Write-Host "  Skipped - no files deleted." -ForegroundColor DarkGray
    }
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor White
Write-Host "  AUDIT COMPLETE" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor White
