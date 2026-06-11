# KVM/QEMU VM Hardening — Full Guide

## Host Side (XML / libvirt)

### 1. Hide Hypervisor from CPUID

Inside `<features>`:

```xml
<kvm>
  <hidden state='on'/>
</kvm>
<hyperv mode='custom'>
  <relaxed state='off'/>
  <vapic state='off'/>
  <spinlocks state='off'/>
  <vendor_id state='on' value='AuthenticAMD'/>
</hyperv>
```

CPU block:

```xml
<cpu mode='host-passthrough' check='none' migratable='off'>
  <feature policy='disable' name='hypervisor'/>
</cpu>
```

### 2. Fix Clock / TSC

```xml
<clock offset='localtime'>
  <timer name='rtc' tickpolicy='catchup'/>
  <timer name='pit' tickpolicy='delay'/>
  <timer name='hpet' present='no'/>
  <timer name='hypervclock' present='no'/>
  <timer name='tsc' present='yes' mode='native'/>
</clock>
```

### 3. Spoof SMBIOS

Replace `<sysinfo>` block with real board values:

```xml
<sysinfo type='smbios'>
  <bios>
    <entry name='vendor'>American Megatrends Inc.</entry>
    <entry name='version'>2601</entry>
    <entry name='date'>09/21/2022</entry>
  </bios>
  <system>
    <entry name='manufacturer'>ASUSTeK COMPUTER INC.</entry>
    <entry name='product'>ROG STRIX B550-F GAMING</entry>
    <entry name='version'>Rev 1.xx</entry>
    <entry name='serial'>M1A0K2C3D4E5</entry>
    <entry name='sku'>SKU</entry>
    <entry name='family'>ASUS MB</entry>
  </system>
  <baseBoard>
    <entry name='manufacturer'>ASUSTeK COMPUTER INC.</entry>
    <entry name='product'>ROG STRIX B550-F GAMING</entry>
    <entry name='version'>Rev 1.xx</entry>
    <entry name='serial'>M1A0K2C3D4E5</entry>
  </baseBoard>
</sysinfo>
```

Also update `<os>` to include:

```xml
<smbios mode='sysinfo'/>
```

And update the `qemu:commandline` SMBIOS arg to match:

```xml
<qemu:arg value='-smbios'/>
<qemu:arg value='type=1,manufacturer=ASUSTeK COMPUTER INC.,product=ROG STRIX B550-F GAMING,version=Rev 1.xx,serial=M1A0K2C3D4E5,uuid=YOUR-UUID-HERE'/>
```

### 4. Fix Network (MAC + Model)

Change MAC prefix away from 52:54:00 (QEMU default) and use e1000e:

```xml
<mac address='00:1B:21:A5:D9:26'/>
<model type='e1000e'/>
```

`00:1B:21` is an Intel OUI. Keep the last 3 octets random.

### 5. Disable memballoon

```xml
<memballoon model='none'/>
```

### 6. Add Disk Serial

Inside your `<disk>` block, before `<alias>`:

```xml
<serial>WD-WXC1A8F3K2L1</serial>
```

### 7. Add Chassis + OEM Strings to SMBIOS

Inside `<sysinfo>`, after `<baseBoard>`:

```xml
<chassis>
  <entry name='manufacturer'>ASUSTeK COMPUTER INC.</entry>
  <entry name='version'>1.0</entry>
  <entry name='serial'>M1A0K2C3D4E5</entry>
  <entry name='asset'>ATN12345678</entry>
  <entry name='sku'>Default string</entry>
</chassis>
<oemStrings>
  <entry>www.asus.com</entry>
</oemStrings>
```

### 8. RAM Modules (SMBIOS Type 17)

In `<qemu:commandline>`, add two entries for realistic DDR4 sticks:

```xml
<qemu:arg value='-smbios'/>
<qemu:arg value='type=17,manufacturer=Kingston,part=KF432C16BB/8,speed=3200,loc_pfx=DIMM_A1,bank=BANK 0,serial=0D2B1A3C'/>
<qemu:arg value='-smbios'/>
<qemu:arg value='type=17,manufacturer=Kingston,part=KF432C16BB/8,speed=3200,loc_pfx=DIMM_B1,bank=BANK 1,serial=1E3C2B4D'/>
```

### 9. Fix Disk Model String

QEMU reports SATA disks as "QEMU HARDDISK" by default. Override via qemu:commandline:

```xml
<qemu:arg value='-set'/>
<qemu:arg value='device.sata0-0-0.model=WDC WD40EZRZ-00WN9B0'/>
```

The device ID `sata0-0-0` corresponds to `sda` (bus=0, target=0, unit=0).

### 10. Remove virtio-serial Controller

Delete this entire block — it shows as "Red Hat VirtIO" in Device Manager:

```xml
<!-- DELETE THIS -->
<controller type='virtio-serial' index='0'>
  <address type='pci' .../>
</controller>
```

### 11. Eject virtio-win ISO

Remove the `<source>` and `<backingStore>` from the CDROM disk entry. Keep the empty CDROM slot but leave it with no media:

```xml
<disk type='file' device='cdrom'>
  <driver name='qemu' type='raw'/>
  <target dev='sdb' bus='sata'/>
  <readonly/>
  <address type='drive' controller='0' bus='0' target='0' unit='1'/>
</disk>
```

### 12. USB Controller Model

Change `qemu-xhci` (QEMU-specific) to `nec-xhci` (NEC/Renesas µPD720201 — real hardware):

```xml
<controller type='usb' index='0' model='nec-xhci' ports='15'>
```

### 13. Apply Changes

```bash
virsh define ~/Downloads/win10_v2.xml
```

Then cold boot the VM (full shutdown, not reboot).

---

## Advanced: ACPI Table Patching (BOCHS → ALASKA)

QEMU hardcodes `BOCHS` as the OEM ID and `BXPC` as the OEM Table ID in its generated ACPI tables (DSDT, FACP, HPET, etc.). This is checked by tools like AIDA64 and some anti-cheats. Your real machine uses `ALASKA` / `A M I ` (AMI BIOS). To match it:

### Step 1: Dump DSDT from inside Windows

Download and run [RWEverything](http://rweverything.com/) or use the Windows built-in:
```cmd
acpidump > acpi.dat
```
Or easier: install `acpica-tools` tools on host and dump via qemu monitor.

**Host-side (simpler):**
```bash
# Copy the running VM's ACPI tables via guest agent or just dump from host QEMU process
sudo cp /sys/firmware/acpi/tables/DSDT /tmp/DSDT.host  # This is HOST — just for reference
```

### Step 2: Extract QEMU's DSDT

While the VM is running, from the QEMU monitor (via virsh):
```bash
virsh qemu-monitor-command win10 --hmp "dump-guest-memory -p /tmp/vm_acpi.dmp"
```

Or simpler: boot VM, inside Windows run:
```powershell
# As Administrator in Windows:
.\acpidump.exe -o acpi_tables.dat
.\acpixtract.exe -a acpi_tables.dat
```

### Step 3: Patch the DSDT

```bash
# Decompile
iasl -d DSDT.dat

# Edit DSDT.dsl — find and replace OEM strings:
# OEM ID:        "BOCHS " → "ALASKA"
# OEM Table ID:  "BXPC    " → "A M I   "
# OEM Revision:  stays as-is

# Recompile
iasl DSDT.dsl  # produces DSDT.aml
```

### Step 4: Inject Patched DSDT

Copy `DSDT.aml` to a stable path (e.g. `/etc/libvirt/qemu/dsdt/win10_dsdt.aml`) then add to qemu:commandline:

```xml
<qemu:arg value='-acpitable'/>
<qemu:arg value='file=/etc/libvirt/qemu/dsdt/win10_dsdt.aml'/>
```

> **Note:** `-acpitable` in QEMU injects an *additional* ACPI table. For DSDT specifically, the OS uses whichever DSDT the firmware provides first, so the patched one takes precedence. Test with AIDA64 → Motherboard → ACPI to verify OEM strings changed.

---

## Guest Side (Inside Windows)

### 1. Disable Hyper-V and VBS

Open cmd as Administrator:

```cmd
bcdedit /set hypervisorlaunchtype off
bcdedit /set vsmlaunchtype off
```

Then: Windows Security → Device Security → Core Isolation Details → Memory Integrity → Off

Reboot.

### 2. Uninstall QEMU Guest Agent

Check Programs and Features (`appwiz.cpl`) and uninstall QEMU guest agent if listed.

Also via cmd:

```cmd
sc query QEMU-GA
sc delete QEMU-GA
```

### 3. Clean Device Manager

Open Device Manager (`devmgmt.msc`) and uninstall (with "delete driver" checked) anything named:

- `VirtIO *`
- `QEMU *`
- `Red Hat VirtIO *`

To show ghosted/leftover devices from previously removed hardware:

```cmd
set DEVMGR_SHOW_NONPRESENT_DEVICES=1
start devmgmt.msc
```

View → Show hidden devices. Uninstall any greyed-out QEMU/virtio entries.

### 4. Registry Cleanup

Open regedit and delete these keys if they exist:

```
HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters
HKLM\HARDWARE\ACPI\DSDT\QEMU
HKLM\HARDWARE\ACPI\FADT\QEMU
HKLM\HARDWARE\ACPI\RSDT\QEMU
```

In `HKLM\SYSTEM\CurrentControlSet\Services` delete any keys named:
`balloon`, `vioserial`, `vioser`, `qemupciserial`, or anything starting with `QEMU`.

### 5. Disable Hyper-V Integration Services

```cmd
sc config vmictimesync start= disabled
sc config vmicheartbeat start= disabled
sc config vmicvss start= disabled
sc config vmicrdv start= disabled
```

### 6. Fix Time Sync

```cmd
sc config w32time start= auto
net start w32time
w32tm /resync /force
```

### 7. Verify

```cmd
msinfo32
```
Should show: `ASUSTeK COMPUTER INC.` / `ROG STRIX B550-F GAMING`

```cmd
wmic bios get manufacturer,smbiosbiosversion
wmic diskdrive get model,serialnumber
wmic nic get name,macaddress
```

All output should be clean — no QEMU, no virtio, no Red Hat.

---

## Summary — Detection Vectors

| Vector | Status | Fix |
|---|---|---|
| CPUID hypervisor bit | ✅ Closed | `kvm hidden` + `hypervisor` feature disabled |
| Hyper-V enlightenments | ✅ Closed | `relaxed/vapic/spinlocks` off, `hypervclock` off |
| SMBIOS type 0/1/2 | ✅ Closed | Real ASUS ROG board values |
| SMBIOS type 3 (chassis) | ✅ Closed | ASUSTeK chassis block added |
| SMBIOS type 11 (OEM strings) | ✅ Closed | `www.asus.com` entry added |
| SMBIOS type 17 (RAM) | ✅ Closed | Kingston DDR4 3200 entries added |
| QEMU MAC prefix (52:54:00) | ✅ Closed | Intel OUI (00:1B:21) |
| virtio NIC | ✅ Closed | Replaced with e1000e |
| virtio memballoon | ✅ Closed | Disabled |
| virtio-serial controller | ✅ Closed | Removed from XML |
| Disk serial missing | ✅ Closed | WD serial added |
| Disk model "QEMU HARDDISK" | ✅ Closed | WDC WD40EZRZ via `-set` override |
| virtio-win ISO mounted | ✅ Closed | CDROM ejected |
| USB controller `qemu-xhci` | ✅ Closed | Changed to `nec-xhci` |
| VBS / Memory Integrity | ✅ Closed | Disabled via bcdedit + Windows Security |
| QEMU guest agent | ✅ Closed | Uninstalled |
| Leftover virtio drivers | ✅ Closed | Removed via Device Manager |
| Hyper-V integration services | ✅ Closed | Disabled |
| TSC timing | ✅ Closed | Native passthrough mode |
| GPU | ✅ Closed | Real RTX 4090 via VFIO passthrough |
| ACPI table OEM strings (BOCHS) | ✅ Closed | qemu-win10-stealth wrapper injects x-oem-id=ALASKA,x-oem-table-id=A M I into -machine arg |
| CPU/SMBIOS platform mismatch (B550/AM4 vs 9950X3D) | ✅ Closed | Updated to ROG CROSSHAIR X670E HERO (AM5) + 9950X3D in SMBIOS type 1/2/4 — CPUID and SMBIOS now consistent |
| vCPU floating / RDTSC jitter | ✅ Closed | vCPUs 0-7 pinned to host cores 8-11 (CPUs 8,24,9,25,10,26,11,27); emulator pinned to 12-15 |
| RDTSC timing (kernel-level) | ⚠️ Open | Add to kernel cmdline: isolcpus=8-11,24-27 nohz_full=8-11,24-27 rcu_nocbs=8-11,24-27 then rebuild grub |
| Dialog confirmation sandbox detection | ⚠️ Open | Guest-side: UAC must be Default level; HKCU\...\OpenSavePidlMRU needs realistic entries; see guest fix notes |
