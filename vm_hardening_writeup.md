# KVM/QEMU Windows 10 VM Hardening — Full Writeup

**Goal:** Defeat VM/sandbox detection tools (pafish, Vanguard anti-cheat) in a KVM/QEMU GPU-passthrough VM on Arch Linux.  
**Host:** AMD Ryzen 9 9950X3D, Arch Linux 7.0.11-arch1-1, NVIDIA RTX 4090 (VFIO passthrough)

---

## Detection Vectors and Fixes

| Vector | Tool | Fix Applied | Status |
|--------|------|-------------|--------|
| ACPI OEM ID `BOCHS` / Creator ID `BXPC` | al-khaser, pafish | Binary patch QEMU → `ALASKA` / `INTL` | ✅ |
| ACPI `WAET` table present | al-khaser | Binary patch signature `WAET` → `WFET` | ✅ |
| ACPI fw_cfg device name `FWCF` in DSDT | al-khaser | Binary patch → `FWGT` | ✅ |
| ACPI fw_cfg HID `QEMU0002` in DSDT | al-khaser | Binary patch → `ACPI0002` | ✅ |
| ACPI fw_cfg HID `QEMU0001` in DSDT | al-khaser | Binary patch → `ACPI0001` | ✅ |
| FADT `Preferred_PM_Profile` = 0 | al-khaser | Runtime memory patch via `/proc/PID/mem` | ✅ |
| SMBIOS board/CPU mismatch | any SMBIOS reader | Updated to X670E HERO + 9950X3D | ✅ |
| RDTSC CPUID timing delta | pafish | Patched kvm-amd.ko TSC compensation | ✅ |
| vCPU migration jitter | pafish RDTSC | CPU pinning in libvirt XML | ✅ |
| CPU frequency (governor) | pafish RDTSC | performance governor on pinned cores | ✅ |
| GetTickCount() low uptime | pafish | Wait 10+ min after boot before testing | ✅ |
| VEN_1B36 PCI device (QEMU virtio) | al-khaser | Deleted via SYSTEM scheduled task + reboot | ✅ |
| `qemu-ga.exe` / QEMU guest agent | al-khaser | Uninstalled QEMU guest agent | ✅ |

---

## 1. ACPI OEM Strings — QEMU Wrapper

**Detection:** ACPI tables include `BOCHS ` or `BXPC` as OEM ID, a universal VM indicator.

**Fix:** A shell wrapper at `/usr/local/bin/qemu-win10-stealth` intercepts the QEMU
`-machine` argument and injects real ASUS OEM strings before passing it through.

```bash
# /usr/local/bin/qemu-win10-stealth
#!/bin/bash
ARGS=()
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-machine" && "$2" == pc-q35-* ]]; then
        ARGS+=("-machine" "${2},x-oem-id=ALASKA,x-oem-table-id=A M I   ")
        shift 2
    else
        ARGS+=("$1")
        shift
    fi
done
exec /usr/bin/qemu-system-x86_64 "${ARGS[@]}"
```

Libvirt's `emulator` path in the VM XML points to this wrapper instead of the real QEMU binary.

---

## 2. SMBIOS Spoofing

**Detection:** Any tool that reads SMBIOS and compares it against the CPU brand string will
detect a mismatch (e.g. AM4 board + AM5 CPU).

**System:** ROG CROSSHAIR X670E HERO (AM5) with BIOS version 3601 (dated 04/03/2025).

In the libvirt VM XML `<sysinfo>` block:
```xml
<sysinfo type='smbios'>
  <bios>
    <entry name='vendor'>American Megatrends International, LLC.</entry>
    <entry name='version'>3601</entry>
    <entry name='date'>04/03/2025</entry>
  </bios>
  <system>
    <entry name='manufacturer'>ASUSTeK COMPUTER INC.</entry>
    <entry name='product'>ROG CROSSHAIR X670E HERO</entry>
    <entry name='version'>Rev 1.xx</entry>
    <entry name='serial'>M8OQAZ123456789</entry>
    <entry name='uuid'>REDACTED</entry>
    <entry name='sku'>SKU</entry>
    <entry name='family'>ROG</entry>
  </system>
  <baseboard>
    <entry name='manufacturer'>ASUSTeK COMPUTER INC.</entry>
    <entry name='product'>ROG CROSSHAIR X670E HERO</entry>
    <entry name='version'>Rev 1.xx</entry>
    <entry name='serial'>M8OQAZ123456789</entry>
  </baseboard>
</sysinfo>
```

In `<qemu:commandline>`, additional SMBIOS types are passed directly to QEMU:
```xml
<!-- SMBIOS type 1 (system) -->
<qemu:arg value='-smbios'/>
<qemu:arg value='type=1,manufacturer=ASUSTeK COMPUTER INC.,product=ROG CROSSHAIR X670E HERO,...'/>

<!-- SMBIOS type 4 (CPU) — must match actual passed-through CPU -->
<qemu:arg value='-smbios'/>
<qemu:arg value='type=4,sock_pfx=AM5,manufacturer=Advanced Micro Devices Inc.,version=AMD Ryzen 9 9950X3D 16-Core Processor,serial=AMD00001,max-speed=5757'/>
```

**Key rule:** SMBIOS type 4 `version` field must match the CPU brand string that CPUID
returns from the passed-through CPU. Mismatches are trivial to detect.

---

## 3. RDTSC CPUID Timing Fix (KVM Kernel Patch)

### The Problem

AMD SVM (hardware virtualization) must trap every CPUID instruction to emulate it in the
hypervisor. This trap — the VM exit + re-entry cycle — costs ~1300–2000 TSC ticks on Zen 5.

pafish detects VMs by bracketing a CPUID with RDTSC:
```asm
rdtsc        ; save tsc_before
cpuid        ; triggers VM exit on hardware
rdtsc        ; save tsc_after
; if (tsc_after - tsc_before) > ~1000: detected as VM
```

On bare metal, CPUID completes in ~100–200 ticks. The VM exit overhead makes it 10-20x
slower, trivially distinguishing virtualized from native execution.

### Contributing Factors Fixed Before the Patch

1. **CPU governor on powersave**: TSC is fixed-rate but with powersave the CPU runs at
   ~1.5 GHz instead of 4.3 GHz, so the VM exit takes ~3x more TSC ticks worth of wall time.
   **Fix:** Set `performance` governor on VM-pinned cores.

2. **vCPU migration**: If a vCPU migrates between physical cores mid-measurement, the TSC
   delta can spike. **Fix:** Pin each vCPU to a dedicated physical thread via `<cputune>`.

   These two fixes alone still leave the timing ~1300 ticks — above the threshold.

### The Patch

**File:** `arch/x86/kvm/svm/svm.c`

Add a wrapper function that measures the time spent handling the CPUID VM exit and
subtracts it from the guest's TSC offset:

```c
static int cpuid_interception(struct kvm_vcpu *vcpu)
{
    struct vcpu_svm *svm = to_svm(vcpu);
    u64 tsc_start, tsc_delta;
    int ret;

    tsc_start = rdtsc_ordered();
    ret = kvm_emulate_cpuid(vcpu);
    tsc_delta = rdtsc_ordered() - tsc_start;

    /*
     * Subtract VM-exit handling overhead from the guest TSC offset so that
     * RDTSC measurements bracketing CPUID appear continuous to the guest.
     */
    svm->vmcb->control.tsc_offset -= tsc_delta;
    vmcb_mark_dirty(svm->vmcb, VMCB_INTERCEPTS);

    return ret;
}
```

In `svm_exit_handlers[]`, replace:
```c
[SVM_EXIT_CPUID]  = kvm_emulate_cpuid,
```
with:
```c
[SVM_EXIT_CPUID]  = cpuid_interception,
```

**Mechanism:** After each CPUID VM exit is emulated, the TSC offset field in the VMCB
(VM Control Block) is decremented by the number of host TSC ticks spent handling the exit.
When the guest next reads RDTSC, the offset makes it appear as though no time passed.

### Build Process

The build requires the full vanilla kernel source matching the running kernel version,
with the Arch LOCALVERSION config to produce matching vermagic.

```bash
# In /tmp/kvm-patch/linux-7.0.11/

# 1. Copy running kernel config
cp /usr/lib/modules/$(uname -r)/build/.config .

# 2. Set vermagic to match running kernel exactly
scripts/config --set-str LOCALVERSION "-arch1-1"
scripts/config --disable LOCALVERSION_AUTO
scripts/config --disable MODULE_SIG_ALL

# 3. Copy symbol versions from installed headers (prevents unresolved symbol warnings)
cp /usr/lib/modules/$(uname -r)/build/Module.symvers .

# 4. Generate arch headers and prepare build tree
make -j$(nproc) ARCH=x86_64 prepare

# 5. Trim config to only build currently-loaded modules (much faster)
LSMOD=/tmp/fake-lsmod.txt make ARCH=x86_64 localmodconfig
# where fake-lsmod.txt contains just: kvm_amd\nkvm

# 6. Apply the patch
python3 apply-patch.py arch/x86/kvm/svm/svm.c

# 7. Build all modules (NOT M=arch/x86/kvm — that skips __modfinal in newer kernels)
make -j$(nproc) ARCH=x86_64 modules
```

**Critical lessons learned:**

- `make M=arch/x86/kvm modules` skips `__modfinal` in Linux 7.x when `KBUILD_EXTMOD` is
  set, so `.ko` files are never produced. Use `make modules` (full build, config-trimmed).

- Module vermagic must match **exactly**: `7.0.11-arch1-1 SMP preempt mod_unload`.
  `CONFIG_LOCALVERSION_AUTO=y` appends a git hash and breaks the match.

- The Arch kernel's `CONFIG_DEBUG_INFO_BTF_MODULES=y` causes `insmod` to reject modules
  whose `.BTF` section was compiled with different debug options. Strip it:
  ```bash
  objcopy --remove-section=.BTF --remove-section=.BTF.ext kvm.ko
  objcopy --remove-section=.BTF --remove-section=.BTF.ext kvm-amd.ko
  ```
  The kernel skips BTF validation entirely when the section is absent.

### Loading the Patched Modules

```bash
# Stop VM, unload stock modules, load patched ones
bash /tmp/kvm-patch/install.sh

# Revert to stock modules if anything is wrong
bash /tmp/kvm-patch/revert.sh
```

---

## 4. CPU Pinning

Prevents vCPU from migrating between physical cores (reduces RDTSC jitter and helps TSC
offset compensation stay accurate).

In the libvirt VM XML `<vcpu placement='static'>8</vcpu>` block and:

```xml
<cputune>
  <vcpupin vcpu='0' cpuset='8'/>
  <vcpupin vcpu='1' cpuset='24'/>
  <vcpupin vcpu='2' cpuset='9'/>
  <vcpupin vcpu='3' cpuset='25'/>
  <vcpupin vcpu='4' cpuset='10'/>
  <vcpupin vcpu='5' cpuset='26'/>
  <vcpupin vcpu='6' cpuset='11'/>
  <vcpupin vcpu='7' cpuset='27'/>
  <emulatorpin cpuset='12-15'/>
</cputune>
```

Cores 8–11 and 24–27 are the second CCD on the 9950X3D (cores 8–15 physical, 24–31
are their SMT siblings). Dedicated to the VM, not used for anything else.

---

## 5. CPU Frequency Governor

**File:** `/etc/systemd/system/vm-cpufreq.service`

```ini
[Unit]
Description=Set performance governor on VM-pinned CPU cores
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'for cpu in 8 9 10 11 24 25 26 27; do echo performance > /sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor; done'

[Install]
WantedBy=multi-user.target
```

Enable once: `sudo systemctl enable --now vm-cpufreq.service`

TSC is a fixed-rate counter (~4.3 GHz on Zen 5). With `powersave` governor the CPU runs
at ~1.5 GHz, so each wall-clock nanosecond of VM exit overhead corresponds to ~3x fewer
TSC ticks — paradoxically making the TSC delta look *smaller*. With `performance`, the
CPU runs at full boost, so the measured delta more accurately represents true wall time.

---

## 6. GetTickCount() Uptime Check

pafish calls `GetTickCount()` and flags the VM if uptime is under ~10 minutes (sandbox
heuristic: sandboxes typically revert to a snapshot and start fresh).

**Fix:** None needed in config. Simply wait at least 10–12 minutes after booting the VM
before running pafish or launching the game.

---

## 7. al-khaser ACPI Table Detections

al-khaser's ACPI checks are split into two functions:

**`qemu_firmware_ACPI()`** — scans the raw bytes of every ACPI table for these strings:
- `"FWCF"` — QEMU firmware-config device name in the DSDT
- `"QEMU0002"` — firmware-config device HID (_HID) in the DSDT
- `"BOCHS"` — default ACPI OEM ID written by QEMU
- `"BXPC"` — default ACPI Creator ID written by QEMU

**`firmware_ACPI()` (generic)** — checks for the presence of a `"WAET"` table signature
(Windows ACPI Emulated devices Table — only generated by QEMU/Hyper-V).

**`firmware_ACPI()` (FADT byte check)** — calls `GetSystemFirmwareTable('ACPI', 'PCAF', ...)`
and checks byte 45 (`Preferred_PM_Profile`). QEMU leaves it `0` (Unspecified); real desktop
hardware sets it `1`.

---

### 7a. Binary Patches to `/usr/bin/qemu-system-x86_64`

All six detectable strings were removed by patching the QEMU binary in-place. Replacements
are chosen to be the same byte length so no surrounding code or table structure shifts.

| Old string | New string | Byte offset | Notes |
|------------|------------|-------------|-------|
| `BOCHS ` (6 B) | `ALASKA` | 9651813 | ACPI OEM ID default |
| `BXPC` (4 B) | `INTL` | various | ACPI Creator ID default |
| `WAET` (4 B) | `WFET` | 9662241 | WAET table signature |
| `FWCF` (4 B) | `FWGT` | 9522274 | fw_cfg device name in DSDT |
| `QEMU0001` (8 B) | `ACPI0001` | 9490506 | fw_cfg/hotplug device HID |
| `QEMU0002` (8 B) | `ACPI0002` | 9522279 | fw_cfg device HID (directly checked) |

Patch script (run once; VM must be stopped; takes effect on next VM start):

```python
data = bytearray(open('/usr/bin/qemu-system-x86_64','rb').read())

patches = {
    b'BOCHS ':   b'ALASKA',
    b'BXPC':     b'INTL',
    b'WAET':     b'WFET',
    b'FWCF':     b'FWGT',
    b'QEMU0001': b'ACPI0001',
    b'QEMU0002': b'ACPI0002',
}

for old, new in patches.items():
    idx = bytes(data).find(old)
    if idx != -1:
        data[idx:idx+len(old)] = new
        print(f'Patched {old} -> {new} at {idx}')

open('/tmp/patched','wb').write(data)
# atomic replace (avoids "text file busy" if QEMU is already running)
# sudo install -m 755 /tmp/patched /usr/bin/qemu-system-x86_64
```

**Note:** `FWCF` and `QEMU0002` sit 5 bytes apart in the binary — they're the device name
and HID of the same AML Device block in the DSDT. Patching both is required.

The `QEMU0002` binary strings are AML string objects inside the DSDT. AML strings are
length-prefixed, so swapping an 8-byte string for another 8-byte string leaves the prefix
intact and keeps the AML bytecode well-formed.

---

### 7b. FADT `Preferred_PM_Profile` — Runtime Memory Patch

**Why not a static binary patch:** The QEMU binary is stripped (no symbols). The FADT is
built entirely at runtime by `build_fadt()` — there is no static table blob in the binary to
patch. The only reliable approach is to patch the field in the live QEMU process memory.

**Why a checksum fix is also required:** ACPI table byte 9 is a checksum such that the
sum of all bytes in the table equals `0 (mod 256)`. Changing byte 45 from `0` to `1`
increments the sum by 1, making the table invalid. Windows' ACPI driver rejects the table
and hangs on boot. The fix: `new_checksum = (old_checksum - 1) & 0xFF`.

**Script:** `/usr/local/bin/patch-fadt-pm-profile`

```python
#!/usr/bin/env python3
# Suspends the VM, patches FACP Preferred_PM_Profile + checksum in QEMU process
# memory, then resumes. Must run as root.
import os, sys, subprocess, time

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "win10"
FACP = b"FACP"
OEM  = b"ALASKA"   # only patch tables with our OEM ID

def virsh(c): subprocess.run(["virsh", c, DOMAIN], capture_output=True)

def get_qemu_pid(domain):
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cl = open(f"/proc/{p}/cmdline").read()
            if "qemu-system-x86_64" in cl and domain in cl:
                return int(p)
        except: pass
    return None

def patch(pid):
    regions = []
    for ln in open(f"/proc/{pid}/maps"):
        pts = ln.split()
        if len(pts) < 2 or 'r' not in pts[1] or 'w' not in pts[1]: continue
        s, e = pts[0].split('-')
        sz = int(e, 16) - int(s, 16)
        if sz < 256 or sz > 32 * 1024**3: continue
        regions.append((int(s, 16), int(e, 16)))

    patched = 0
    with open(f"/proc/{pid}/mem", 'r+b') as mem:
        for s, e in regions:
            off = 0
            while off < e - s:
                csz = min(64 * 1024 * 1024, e - s - off)
                ab  = s + off
                try:
                    mem.seek(ab); d = mem.read(csz)
                except: break
                i = 0
                while True:
                    p = d.find(FACP, i)
                    if p < 0: break
                    if p + 46 < len(d) and d[p+10:p+16] == OEM:
                        at = ab + p
                        b9, b45 = d[p+9], d[p+45]
                        if b45 == 0:
                            mem.seek(at + 45); mem.write(b'\x01')
                            # fix checksum so sum of all bytes stays 0 mod 256
                            mem.seek(at + 9);  mem.write(bytes([(b9 - 1) & 0xFF]))
                            patched += 1
                    i = p + 1
                off += csz
    return patched

pid = get_qemu_pid(DOMAIN)
virsh("suspend"); time.sleep(0.2)
n = patch(pid)
virsh("resume")
```

**How it's invoked:** `start-vm4.sh` launches this in the background 5 seconds after
`virsh start win10`. The 5-second delay lets QEMU fully initialize before the scan.
Windows kernel boots ~15–20 seconds in and caches ACPI tables then — leaving a comfortable
window. The VM is suspended for ~200 ms during the scan, which is imperceptible.

The scanner finds FACP tables in two locations in QEMU's address space:
1. The fw_cfg GArray heap buffer (QEMU's own copy)
2. Guest RAM (the copy OVMF placed there for the guest ACPI table list)

Both are patched. The Windows ACPI driver reads from the guest RAM copy via the UEFI
ACPI table list, so that copy is the critical one.

---

## Files Summary

| Path | Purpose |
|------|---------|
| `/usr/bin/qemu-system-x86_64` | QEMU binary (patched in-place for ACPI strings) |
| `/usr/local/bin/qemu-win10-stealth` | QEMU wrapper — patches ACPI OEM strings at runtime |
| `/usr/local/bin/patch-fadt-pm-profile` | Patches FADT Preferred_PM_Profile + checksum in live QEMU memory |
| `~/start-vm4.sh` | VM start script — runs FADT patcher 5s after boot |
| Libvirt VM XML (`virsh dumpxml win10`) | SMBIOS, CPU pinning, USB passthrough config |
| `/etc/systemd/system/vm-cpufreq.service` | Performance governor on VM-pinned cores |
| `/etc/modprobe.d/kvm-amd-options.conf` | Enables AVIC (`avic=1`) for kvm_amd |
| `/tmp/kvm-patch/apply-patch.py` | Applies TSC compensation patch to svm.c |
| `/tmp/kvm-patch/build.sh` | Builds patched kvm.ko and kvm-amd.ko |
| `/tmp/kvm-patch/install.sh` | Loads patched modules (backs up originals) |
| `/tmp/kvm-patch/revert.sh` | Restores stock KVM modules |

---

## What's Left for Vanguard

Pafish should be clean after the above. Vanguard 2.0 additionally checks:

- **Secure Boot**: Vanguard prefers Secure Boot to be enabled. QEMU supports this via
  OVMF + UEFI keys. Configure OVMF with `secboot` firmware variant and enroll MS keys.
- **TPM PCR values**: The emulated `swtpm` has valid PCR structure but PCR values
  differ from a real TPM (no real boot chain measurements). Vanguard may not check PCRs
  deeply, but this is an area to watch.
- **CPUID hypervisor bit (leaf 0x1, ECX bit 31)**: Should be 0. Verify with
  `cpuid -l 0x1` inside the VM — AVIC typically does not expose this.
- **Driver signing / kernel integrity**: Vanguard flags unsigned kernel drivers on the
  *guest* OS. Ensure Windows is in normal mode, not test signing mode.

---

## 8. PCI Subsystem Vendor ID Fix (Red Hat → ASUS)

**Detection:** Windows Device Manager shows `SUBSYS_11001AF4` on Q35/ICH9 PCI devices.
`0x1AF4` is the Red Hat/QEMU vendor ID — a direct VM fingerprint visible to any tool
that reads PCI config space (including Vanguard's kernel driver).

**Fix:** Binary patch `/usr/bin/qemu-system-x86_64` at the MCH subsystem initialization
code path which writes to PCI config offsets 0x2C/0x2E (subsystem vendor/device fields):

```python
data = bytearray(open('/usr/bin/qemu-system-x86_64','rb').read())

# Offset 0x3e79c1: subsystem vendor 0x1AF4 (Red Hat) -> 0x1043 (ASUSTeK)
data[0x3e79c1:0x3e79c5] = bytes([0x43, 0x10, 0x00, 0x00])

# Offset 0x3e79c7: subsystem device 0x1100 -> 0x8694 (ASUS ROG board device ID)
data[0x3e79c7:0x3e79cb] = bytes([0x94, 0x86, 0x00, 0x00])

open('/tmp/patched','wb').write(data)
sudo install -m 755 /tmp/patched /usr/bin/qemu-system-x86_64
```

Values are stored little-endian in the binary. Target ASUS IDs: vendor `0x1043`, device `0x8694`.

---

## 9. HDA Codec Vendor ID Fix (Red Hat → Realtek)

**Detection:** Windows shows `HDAUDIO\FUNC_01&VEN_1AF4&DEV_0022` for the VM's HDA audio codec.
`VEN_1AF4` is Red Hat — trivially detected.

**Fix:** Binary patch three occurrences of the AC_PAR_VENDOR_ID node parameter in the
`.rodata` section of `/usr/bin/qemu-system-x86_64`. The value `0x1AF40022` (stored as
LE `22 00 F4 1A`) is replaced with `0x10EC0887` (Realtek ALC887, LE `87 08 EC 10`):

```python
data = bytearray(open('/usr/bin/qemu-system-x86_64','rb').read())

old = bytes([0x22, 0x00, 0xF4, 0x1A])
new = bytes([0x87, 0x08, 0xEC, 0x10])

# Three occurrences in .rodata at: 0xa3b8ec, 0xa3b944, 0xa3b94c
count = 0
idx = 0
while True:
    pos = bytes(data).find(old, idx)
    if pos == -1: break
    data[pos:pos+4] = new
    print(f'Patched at 0x{pos:x}')
    count += 1
    idx = pos + 4

open('/tmp/patched','wb').write(data)
sudo install -m 755 /tmp/patched /usr/bin/qemu-system-x86_64
```

Result: Windows enumerates `HDAUDIO\FUNC_01&VEN_10EC&DEV_0887` — Realtek ALC887,
present in real ASUS ROG boards.

---

## 10. DVD-ROM / SCSI Registry Cleanup

**Detection:** Windows `HKLM\HARDWARE\DEVICEMAP\Scsi` contained `QEMU DVD-ROM` — populated
from the ATAPI SCSI INQUIRY response which is hardcoded in QEMU's `atapi.c`.

**Fix:** Remove the CD-ROM device entirely from the VM XML. No CD-ROM = no SCSI INQUIRY =
no registry entry. In the libvirt XML, delete the entire `<disk device='cdrom'>` block and
remove `<boot dev='cdrom'/>` from the `<os>` section.

The `-global ide-cd.model=...` qemu:commandline arg was also removed since there is no
longer a CD-ROM device to apply it to.

---

## 11. USB Hostdev Address Drift Fix

**Problem:** GK61 keyboard USB passthrough broke on reboot because `bus`/`device` numbers
in the USB hostdev `<source>` were hardcoded and the device number shifts between reboots.

**Fix:** Remove the `<address>` element from the `<source>` block entirely. libvirt then
matches the device by VID/PID only, which is stable:

```xml
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <vendor id='0x32e3'/>
    <product id='0x00f7'/>
    <!-- no <address> element — match by VID/PID only -->
  </source>
  <address type='usb' bus='0' port='2'/>
</hostdev>
```

---

## 12. VM UUID Rotation (Vanguard Purge)

**Problem:** Vanguard sets a persistent detection flag (survives reboots) once it detects
a VM. The flag is tied to the SMBIOS UUID. Changing the UUID and purging all Vanguard
artifacts forces it to treat the machine as new.

**Procedure:**

1. Generate new UUID on host: `python3 -c "import uuid; print(uuid.uuid4())"`
2. Update both occurrences in `/etc/libvirt/qemu/win10.xml`:
   - `<uuid>` element (line ~3)
   - `-smbios type=1,...,uuid=` qemu:commandline arg
3. Inside Windows (before shutting down):
   - Run `randomize-machine-id.ps1` (served via `http://192.168.122.1:8080/`)
   - Run `vm-audit.ps1` — say `y` to all deletion prompts (VirtIO registry keys + Vanguard artifacts)
   - Stop vgk/vgc services: `sc.exe stop vgk; sc.exe stop vgc`
4. Shut down Windows VM fully
5. `sudo systemctl reload libvirtd` to pick up the new XML
6. Start VM, reinstall Vanguard via Riot client

**Current UUID:** `8e2abb6d-d14f-497b-8b0a-8385c112959b` (rotated 2026-06-11)

---

## 13. Windows Identity Randomizer (`randomize-machine-id.ps1`)

Script served at `http://192.168.122.1:8080/randomize-machine-id.ps1`.
Run as Administrator inside Windows. Randomizes:

| Identifier | Method |
|---|---|
| MachineGuid | Registry `HKLM\SOFTWARE\Microsoft\Cryptography` |
| ComputerName | Random `DESKTOP-XXXXXXX`, applied via `Rename-Computer` |
| NIC MAC address | Intel OUI `00-1B-21-XX-XX-XX` via `NetworkAddress` registry key |
| Windows ProductId | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| InstallDate | Random date 180-900 days ago |
| SQMClient MachineId | Registry `HKLM\SOFTWARE\Microsoft\SQMClient` |
| WindowsUpdate SusClientId | Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate` |
| DiagTrack device IDs | Multiple registry keys under DiagTrack |
| DPAPI ProviderID | Registry `HKLM\SYSTEM\...\LSA\Data` |
| NVIDIA driver GUID | Registry under `HKLM\SYSTEM\...\DriverDatabase` |
| PnP Hardware Profile GUID | Registry `HKLM\SYSTEM\...\HardwareProfiles` |
| NTFS volume serial (C:) | Direct boot sector write at offset 0x48 |
| Machine SID | Via SYSTEM scheduled task (runs at next boot) |

Does NOT change: CPU serial (SMBIOS), HDD serial (set in VM XML), BIOS/board serials (SMBIOS).

**Note:** File had em-dash/smart-quote encoding issues breaking PowerShell. Fixed with:
```python
import re
content = open('randomize-machine-id.ps1').read()
content = re.sub(r'[^\x00-\x7F]', '-', content)
open('randomize-machine-id.ps1', 'w').write(content)
```

---

## Updated Detection Vector Status

| Vector | Status | Fix |
|---|---|---|
| PCI SUBSYS vendor 0x1AF4 (Red Hat) | ✅ Closed | Binary patch MCH subsystem → 0x1043 (ASUS) |
| HDAUDIO VEN_1AF4 (Red Hat codec) | ✅ Closed | Binary patch .rodata AC_PAR_VENDOR_ID → 0x10EC0887 (Realtek ALC887) |
| SCSI "QEMU DVD-ROM" registry entry | ✅ Closed | CD-ROM device removed from VM XML entirely |
| USB keyboard passthrough drift | ✅ Closed | Match by VID/PID only, no address element |
| Vanguard persistent detection flag | ✅ Closed (procedure) | UUID rotation + full artifact purge + reinstall |
